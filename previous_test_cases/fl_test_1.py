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

# 1) Dataset: MNIST 0 vs 1 with IID distribution for 3 clients (reduced size for testing)
transform = transforms.Compose([
    transforms.ToTensor(),  # Scales to [0,1]
])
full_train = datasets.MNIST(root="./data", train=True, download=True, transform=transform)

# Filter for labels 0 or 1
idxs = [i for i, (_, label) in enumerate(full_train) if label in (0, 1)]
# Subsample for testing (100 samples per client)
n_total_test = 300
idxs = idxs[:n_total_test]
full_subset = Subset(full_train, idxs)

# Split indices into 3 IID subsets
n_clients = 3
samples_per_client = n_total_test // n_clients
random.shuffle(idxs)

client_indices = [
    idxs[i * samples_per_client:(i + 1) * samples_per_client]
    for i in range(n_clients)
]
# Handle remaining samples
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
            nn.Conv2d(1, 8, kernel_size=3, stride=1, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(kernel_size=2, stride=2)
        )
        self.layer2 = nn.Sequential(
            nn.Conv2d(8, 16, kernel_size=3, stride=1, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(kernel_size=2, stride=2)
        )
        self.flatten = nn.Flatten()
        self.feat = nn.Linear(16 * 7 * 7, 16)
        self.fc = nn.Linear(16, 1)
        self.act = nn.Sigmoid()
        nn.init.xavier_uniform_(self.feat.weight)
        nn.init.xavier_uniform_(self.fc.weight)

    def forward(self, x):
        x = self.layer1(x)
        x = self.layer2(x)
        x = self.flatten(x)
        feats = torch.relu(self.feat(x))
        out = self.act(self.fc(feats))
        return out, feats

# 3) Client class for local training, feature extraction, and encryption
class Client:
    def __init__(self, client_id, dataset, device):
        self.id = client_id
        self.loader = DataLoader(dataset, batch_size=64, shuffle=True)
        self.model = CNN().to(device)
        self.criterion = nn.BCELoss()
        self.optimizer = optim.Adam(self.model.parameters(), lr=0.001)
        self.device = device
        self.n_samples = len(dataset)

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
        return np.vstack(features)

    def get_fc_weights(self):
        return self.model.fc.weight.detach().cpu().numpy().reshape(-1)

    def encrypt_features(self, fe, tag, start_idx, scale=100000):
        X_feat = self.extract_features()
        X_int = np.round(X_feat * scale).astype(int)
        return [
            FeDDHMultiClient.encrypt(
                X_int[i].tolist(),
                tag,
                fe.get_enc_key(start_idx + i)
            )
            for i in range(X_int.shape[0])
        ], X_int

    def encrypt_weights(self, fe, tag, client_idx, scale=100000):
        w = self.get_fc_weights()
        w_int = np.round(w * scale).astype(int)
        return FeDDHMultiClient.encrypt(
            w_int.tolist(),
            tag,
            fe.get_enc_key(client_idx)
        ), w_int

# 4) Initialize clients
clients = [Client(i, dataset, device) for i, dataset in enumerate(client_datasets)]

# 5) Train each client locally
for client in clients:
    print(f"\nTraining Client {client.id+1}")
    client.train(epochs=10)

# 6) Secure aggregation using FeDDHMultiClient (FedAvg)
tag = b"pytorch-cnn-fe"
scale = 100000  # Increased scale for precision
n_total = sum(client.n_samples for client in clients)  # 300 for testing
m = 16  # Feature dimension

# Initialize DMCFE for features and weights
fe_features = FeDDHMultiClient.generate(n_total, m)
fe_weights = FeDDHMultiClient.generate(n_clients, m)

# Encrypt features and weights
client_enc_features = []
client_X_int = []
offset = 0
for client in clients:
    enc_feats, X_int = client.encrypt_features(fe_features, tag, offset, scale)
    client_enc_features.extend(enc_feats)
    client_X_int.append(X_int)
    offset += client.n_samples

client_enc_weights = []
client_w_int = []
for i, client in enumerate(clients):
    enc_w, w_int = client.encrypt_weights(fe_weights, tag, i, scale)
    client_enc_weights.append(enc_w)
    client_w_int.append(w_int)

# Securely aggregate weights (FedAvg)
avg_func = np.full((n_clients, m), 1.0 / n_clients)  # Shape (3, 16)
avg_func_int = np.round(avg_func * scale).astype(int)
print(f"avg_func_int shape: {avg_func_int.shape}")
sk_weights = FeDDHMultiClient.keygen(avg_func_int.tolist(), fe_weights)
y_int_raw = FeDDHMultiClient.decrypt(
    client_enc_weights,
    tag,
    fe_weights.get_public_key(),
    sk_weights,
    (-10**12, 10**12)
)
print(f"y_int_raw: {y_int_raw}, type: {type(y_int_raw)}")
# Ensure y_int is a vector of length m=16
if isinstance(y_int_raw, (list, np.ndarray)):
    y_int = np.array(y_int_raw).astype(int)
else:
    # Fallback: Average plaintext weights for debugging
    print("Warning: y_int_raw is not a vector, using plaintext average for debugging")
    y_int = np.mean(client_w_int, axis=0).astype(int)
print(f"y_int shape: {y_int.shape}, values: {y_int}")

# 7) Use aggregated weights for feature inner product
X_int = np.vstack(client_X_int)  # Shape (n_total, 16)
print(f"X_int shape: {X_int.shape}, y_int shape: {y_int.shape}")
y_mat = np.tile(y_int, (n_total, 1))  # Shape: (n_total, m)
print(f"y_mat shape: {y_mat.shape}")
sk_features = FeDDHMultiClient.keygen(y_mat.tolist(), fe_features)

# Decrypt to compute Σ⟨xᵢ, y⟩
result = FeDDHMultiClient.decrypt(
    client_enc_features,
    tag,
    fe_features.get_public_key(),
    sk_features,
    (-10**15, 10**15)
)

# Validate result
expected_result = np.sum(X_int @ y_int)
print("\nDecrypted Σ⟨xᵢ, y⟩ =", result)
print("Expected Σ⟨xᵢ, y⟩ =", expected_result)

# Fallback: Compute partial inner products per client
partial_results = []
for i, X_int_client in enumerate(client_X_int):
    partial_sum = np.sum(X_int_client @ y_int)
    partial_results.append(partial_sum)
    print(f"Client {i+1} partial Σ⟨xᵢ, y⟩ =", partial_sum)
print("Sum of partial results =", sum(partial_results))