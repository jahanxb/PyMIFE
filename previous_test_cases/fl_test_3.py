import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Subset
import torchvision
from torchvision import datasets, transforms
from mife.multiclient.rom.ddh import FeDDHMultiClient
import numpy as np
import random
from multiprocessing import Pool, set_start_method, freeze_support
import logging
from tqdm import tqdm

# Set spawn start method for CUDA compatibility
set_start_method('spawn', force=True)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set random seed for reproducibility
torch.manual_seed(42)
np.random.seed(42)
random.seed(42)

# 1) Dataset: MNIST 0 vs 1 with IID distribution for 3 clients (reduced for testing)
transform = transforms.Compose([
    transforms.ToTensor(),  # Scales to [0,1]
])

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
            logging.info(f"Client {self.id+1}, Epoch {epoch+1} loss: {total_loss/len(self.loader):.4f}")

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

    def encrypt_features(self, fe, tag, start_idx, scale=1000):
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

    def encrypt_weights(self, fe, tag, client_idx, scale=1000):
        w = self.get_fc_weights()
        w_int = np.round(w * scale).astype(int)
        return FeDDHMultiClient.encrypt(
            w_int.tolist(),
            tag,
            fe.get_enc_key(client_idx)
        ), w_int

def decrypt_weight_dimension(dim):
    func_dim = np.zeros((n_clients, m))
    func_dim[:, dim] = 1.0 / n_clients
    func_dim_int = np.round(func_dim * scale).astype(int)
    sk_dim = FeDDHMultiClient.keygen(func_dim_int.tolist(), fe_weights)
    val = FeDDHMultiClient.decrypt(
        client_enc_weights,
        tag,
        fe_weights.get_public_key(),
        sk_dim,
        (-10**12, 10**12)
    )
    return dim, int(val) if isinstance(val, (int, float)) else val[0]

def process_client(client_idx):
    client = clients[client_idx]
    # Initialize MCFE for client
    fe_client = FeDDHMultiClient.generate(client.n_samples, m)
    # Encrypt features
    enc_feats, X_int_client = client.encrypt_features(fe_client, tag, 0, scale)
    # Compute inner product
    y_mat_client = np.tile(y_int, (client.n_samples, 1))  # Shape: (n_samples, m)
    sk_client = FeDDHMultiClient.keygen(y_mat_client.tolist(), fe_client)
    result_client = FeDDHMultiClient.decrypt(
        enc_feats,
        tag,
        fe_client.get_public_key(),
        sk_client,
        (-10**12, 10**12)
    )
    return client_idx, result_client, X_int_client

n_clients = 3
m = 16
tag = b"pytorch-cnn-fe"
scale = 1000  # Reduced scale
client_enc_weights = []
client_w_int = []


fe_weights = FeDDHMultiClient.generate(n_clients, m)

if __name__ == '__main__':
    
    
    freeze_support()  # Optional, for frozen executables
    full_train = datasets.MNIST(root="./data", train=True, download=True, transform=transform)

    # Filter for labels 0 or 1
    idxs = [i for i, (_, label) in enumerate(full_train) if label in (0, 1)]
    # Subsample for testing (10 samples per client)
    n_total_test = 30  # Increase to 300 or remove for full dataset (~12665)
    idxs = idxs[:n_total_test]
    full_subset = Subset(full_train, idxs)

    # Split indices into 3 IID subsets
    
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
    logging.info(f"torch: {torch.__version__}, CUDA available? {torch.cuda.is_available()}")
    logging.info(f"torchvision: {torchvision.__version__}")

    # Verify class distribution for IID
    for i, dataset in enumerate(client_datasets):
        labels = [full_train[idx][1] for idx in client_indices[i]]
        zeros = sum(1 for label in labels if label == 0)
        ones = sum(1 for label in labels if label == 1)
        logging.info(f"Client {i+1}: {len(labels)} samples, {zeros} zeros, {ones} ones")

    # 4) Initialize clients
    clients = [Client(i, dataset, device) for i, dataset in enumerate(client_datasets)]

    # 5) Train each client locally
    for client in clients:
        logging.info(f"\nTraining Client {client.id+1}")
        client.train(epochs=10)

    # 6) Secure aggregation using FeDDHMultiClient (FedAvg)
    
    n_total = sum(client.n_samples for client in clients)  # 30 for testing
      # Feature dimension

    # Initialize DMCFE for weights
    fe_weights = FeDDHMultiClient.generate(n_clients, m)

    # Encrypt weights
    
    for i, client in enumerate(clients):
        enc_w, w_int = client.encrypt_weights(fe_weights, tag, i, scale)
        client_enc_weights.append(enc_w)
        client_w_int.append(w_int)

    # Securely aggregate weights (FedAvg) with parallel decryption
    avg_func = np.full((n_clients, m), 1.0 / n_clients)  # Shape (3, 16)
    avg_func_int = np.round(avg_func * scale).astype(int)
    logging.info(f"avg_func_int shape: {avg_func_int.shape}")
    sk_weights = FeDDHMultiClient.keygen(avg_func_int.tolist(), fe_weights)

    # Parallel weight decryption
    logging.info("Decrypting weight dimensions in parallel")
    with Pool(processes=8) as pool:  # Limit processes to avoid contention
        results = list(tqdm(pool.imap(decrypt_weight_dimension, range(m)), total=m))
    y_int = np.zeros(m, dtype=int)
    for dim, val in sorted(results):
        y_int[dim] = val
    logging.info(f"y_int shape: {y_int.shape}, values: {y_int}")

    # 7) Compute per-client inner products
    client_results = []
    client_X_int = []

    # Parallel processing for clients
    logging.info(f"Processing {n_clients} clients in parallel")
    with Pool(processes=8) as pool:  # Limit processes
        results = list(tqdm(pool.imap(process_client, range(n_clients)), total=n_clients))
    for client_idx, result_client, X_int_client in sorted(results):
        client_results.append(result_client)
        client_X_int.append(X_int_client)
        logging.info(f"Client {client_idx+1} inner product: {result_client}")

    # Aggregate client results securely
    fe_agg = FeDDHMultiClient.generate(n_clients, 1)  # m=1 for scalar sum
    enc_results = [
        FeDDHMultiClient.encrypt([int(res)], tag, fe_agg.get_enc_key(i))
        for i, res in enumerate(client_results)
    ]
    sum_func = np.ones((n_clients, 1))  # Sum all client results
    sum_func_int = np.round(sum_func * scale).astype(int)
    sk_agg = FeDDHMultiClient.keygen(sum_func_int.tolist(), fe_agg)
    result = FeDDHMultiClient.decrypt(
        enc_results,
        tag,
        fe_agg.get_public_key(),
        sk_agg,
        (-10**15, 10**15)
    )
    logging.info(f"Decrypted Σ⟨xᵢ, y⟩ = {result}")

    # Validate result
    X_int = np.vstack(client_X_int)  # Shape (n_total, 16)
    expected_result = np.sum(X_int @ y_int)
    logging.info(f"Expected Σ⟨xᵢ, y⟩ = {expected_result}")

    # Compute partial inner products per client for validation
    partial_results = []
    for i, X_int_client in enumerate(client_X_int):
        partial_sum = np.sum(X_int_client @ y_int)
        partial_results.append(partial_sum)
        logging.info(f"Client {i+1} partial Σ⟨xᵢ, y⟩ = {partial_sum}")
    logging.info(f"Sum of partial results = {sum(partial_results)}")