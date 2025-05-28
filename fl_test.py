import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Subset
import torchvision
from torchvision import datasets, transforms
from mife.multiclient.rom.ddh import FeDDHMultiClient
import numpy as np
import random

# Set random seed for reproducibility
torch.manual_seed(42)
np.random.seed(42)
random.seed(42)

# 1) Dataset: MNIST 0 vs 1 with IID distribution for 3 clients
transform = transforms.Compose([
    transforms.ToTensor(),  # Scales to [0,1]
])
full_train = datasets.MNIST(root="./data", train=True, download=True, transform=transform)

# Filter for labels 0 or 1
idxs = [i for i, (_, label) in enumerate(full_train) if label in (0, 1)]
full_subset = Subset(full_train, idxs)

# Split indices into 3 IID subsets
n_samples = len(full_subset)
n_clients = 3
samples_per_client = n_samples // n_clients
random.shuffle(idxs)  # Shuffle for IID distribution

client_indices = [
    idxs[i * samples_per_client:(i + 1) * samples_per_client]
    for i in range(n_clients)
]
# Handle remaining samples (if any)
for i, idx in enumerate(idxs[n_clients * samples_per_client:]):
    client_indices[i].append(idx)

# Create client datasets and loaders
client_datasets = [Subset(full_train, indices) for indices in client_indices]
client_loaders = [DataLoader(dataset, batch_size=64, shuffle=True) for dataset in client_datasets]

device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

# Verify versions
print("torch:", torch.__version__, "CUDA available?", torch.cuda.is_available())
print("torchvision:", torchvision.__version__)

# Verify class distribution for IID
for i, dataset in enumerate(client_datasets):
    labels = [full_train[idx][1] for idx in client_indices[i]]
    zeros = sum(1 for label in labels if label == 0)
    ones = sum(1 for label in labels if label == 1)
    print(f"Client {i+1}: {len(labels)} samples, {zeros} zeros, {ones} ones")

# 2) Define CNN suitable for MNIST
class CNN(nn.Module):
    def __init__(self):
        super(CNN, self).__init__()
        self.layer1 = nn.Sequential(
            nn.Conv2d(1, 8, kernel_size=3, stride=1, padding=1),  # [1, 28, 28] -> [8, 28, 28]
            nn.ReLU(),
            nn.MaxPool2d(kernel_size=2, stride=2)  # [8, 28, 28] -> [8, 14, 14]
        )
        self.layer2 = nn.Sequential(
            nn.Conv2d(8, 16, kernel_size=3, stride=1, padding=1),  # [8, 14, 14] -> [16, 14, 14]
            nn.ReLU(),
            nn.MaxPool2d(kernel_size=2, stride=2)  # [16, 14, 14] -> [16, 7, 7]
        )
        self.flatten = nn.Flatten()
        self.feat = nn.Linear(16 * 7 * 7, 16)  # [16*7*7=784] -> [16]
        self.fc = nn.Linear(16, 1)  # [16] -> [1]
        self.act = nn.Sigmoid()
        # Initialize weights
        nn.init.xavier_uniform_(self.feat.weight)
        nn.init.xavier_uniform_(self.fc.weight)

    def forward(self, x):
        x = self.layer1(x)
        x = self.layer2(x)
        x = self.flatten(x)  # [batch, 16*7*7]
        feats = torch.relu(self.feat(x))  # [batch, 16]
        out = self.act(self.fc(feats))  # [batch, 1]
        return out, feats  # Return (prediction, features)

# 3) Client class for local training and feature extraction
class Client:
    def __init__(self, client_id, dataset, device):
        self.id = client_id
        self.loader = DataLoader(dataset, batch_size=64, shuffle=True)
        self.model = CNN().to(device)
        self.criterion = nn.BCELoss()
        self.optimizer = optim.Adam(self.model.parameters(), lr=0.001)
        self.device = device

    def train(self, epochs=10):
        self.model.train()
        for epoch in range(epochs):
            total_loss = 0.0
            for imgs, labels in self.loader:
                imgs = imgs.to(self.device)
                labels = labels.float().unsqueeze(1).to(self.device)
                self.optimizer.zero_grad()
                preds, _ = self.model(imgs)
                loss = self.criterion(preds, labels)
                loss.backward()
                self.optimizer.step()
                total_loss += loss.item()
            print(f"Client {self.id+1}, Epoch {epoch+1} loss: {total_loss/len(self.loader):.4f}")

    def extract_features(self, batch_size=256):
        self.model.eval()
        features = []
        with torch.no_grad():
            for imgs, _ in DataLoader(self.loader.dataset, batch_size=batch_size):
                imgs = imgs.to(self.device)
                _, feats = self.model(imgs)
                features.append(feats.cpu().numpy())
        return np.vstack(features)  # Shape (n_client, 16)

    def get_fc_weights(self):
        return self.model.fc.weight.detach().cpu().numpy().reshape(-1)

# 4) Initialize clients
clients = [Client(i, dataset, device) for i, dataset in enumerate(client_datasets)]

# 5) Train each client locally
for client in clients:
    print(f"\nTraining Client {client.id+1}")
    client.train(epochs=10)

# 6) Extract features and weights from each client
client_features = [client.extract_features() for client in clients]
client_weights = [client.get_fc_weights() for client in clients]

# Aggregate features and weights
X_feat = np.vstack(client_features)  # Shape (n_total, 16)
y_vec = np.mean(client_weights, axis=0)  # Average weights across clients, shape (16,)
n_total, m = X_feat.shape  # n_total ≈ 12665, m = 16

# 7) Quantize to integers
scale = 1000
X_int = np.round(X_feat * scale).astype(int)
y_int = np.round(y_vec * scale).astype(int)

# 8) Run FeDDHMultiClient with decentralized key generation
tag = b"pytorch-cnn-fe"
fe = FeDDHMultiClient.generate(n_total, m)

# Encrypt each feature vector (client-specific)
cs = []
offset = 0
for i, client_X_int in enumerate([np.round(client_features[i] * scale).astype(int) for i in range(n_clients)]):
    n_client = client_X_int.shape[0]
    client_cs = [
        FeDDHMultiClient.encrypt(
            client_X_int[j].tolist(),
            tag,
            fe.get_enc_key(offset + j)
        )
        for j in range(n_client)
    ]
    cs.extend(client_cs)
    offset += n_client

# Create a matrix by repeating y_int n_total times to match expected shape (n_total, m)
y_mat = np.tile(y_int, (n_total, 1))  # Shape: (n_total, m) = (12665, 16)

# Generate secret key (clients collaborate)
sk = FeDDHMultiClient.keygen(y_mat.tolist(), fe)

# Decrypt to compute Σ⟨xᵢ, y⟩
result = FeDDHMultiClient.decrypt(
    cs, tag,
    fe.get_public_key(),
    sk,
    (0, 10**12)
)

# Validate result by computing unencrypted inner product
expected_result = np.sum(X_int @ y_int)
print("\nDecrypted Σ⟨xᵢ, y⟩ =", result)
print("Expected Σ⟨xᵢ, y⟩ =", expected_result)