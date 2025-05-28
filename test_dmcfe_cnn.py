import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Subset
import torchvision
from torchvision import datasets, transforms
from mife.multiclient.rom.ddh import FeDDHMultiClient
import numpy as np

# 1) Dataset: MNIST 0 vs 1
transform = transforms.Compose([
    transforms.ToTensor(),  # Scales to [0,1]
])
full_train = datasets.MNIST(root="./data", train=True, download=True, transform=transform)
# Filter for labels 0 or 1
idxs = [i for i, (_, label) in enumerate(full_train) if label in (0, 1)]
train_subset = Subset(full_train, idxs)
loader = DataLoader(train_subset, batch_size=64, shuffle=True)

device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

# Verify versions
print("torch:", torch.__version__, "CUDA available?", torch.cuda.is_available())
print("torchvision:", torchvision.__version__)

# 2) Define tiny CNN
class TinyCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.conv = nn.Conv2d(1, 8, kernel_size=3, padding=1)
        self.pool = nn.MaxPool2d(2, 2)
        self.flatten = nn.Flatten()
        self.feat = nn.Linear(8 * 14 * 14, 16)  # Feature dim m = 16
        self.out = nn.Linear(16, 1)
        self.act = nn.Sigmoid()

    def forward(self, x):
        x = torch.relu(self.conv(x))
        x = self.pool(x)
        x = self.flatten(x)
        x = torch.relu(self.feat(x))
        return self.act(self.out(x)), x  # Return (prediction, features)

# model = TinyCNN().to(device)
# criterion = nn.BCELoss()
# optimizer = optim.Adam(model.parameters(), lr=1e-3)



class CNN(torch.nn.Module):

    def __init__(self):
        super(CNN, self).__init__()
        self.layer1 = torch.nn.Sequential(
            torch.nn.Conv2d(1, 8, kernel_size=3, stride=1, padding=1),
            torch.nn.ReLU(),
            torch.nn.MaxPool2d(kernel_size=2, stride=2))
        self.layer2 = torch.nn.Sequential(
            torch.nn.Conv2d(3, 3, kernel_size=3, stride=1, padding=1),
            torch.nn.ReLU(),
            torch.nn.MaxPool2d(kernel_size=2, stride=2))
        self.fc = torch.nn.Linear(3 * 32 * 32, 2, bias=True)
        torch.nn.init.xavier_uniform_(self.fc.weight)

    def forward(self, x):
        out = self.layer1(x)
        out = self.layer2(out)
        out = out.view(out.size(0), -1)   
        out = self.fc(out)
        return out


model = CNN().to(device)
criterion = nn.BCELoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)


# 3) Train briefly
model.train()
for epoch in range(10):
    total_loss = 0.0
    for imgs, labels in loader:
        imgs = imgs.to(device)
        labels = labels.float().unsqueeze(1).to(device)
        optimizer.zero_grad()
        preds, _ = model(imgs)
        loss = criterion(preds, labels)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()
    print(f"Epoch {epoch+1} loss: {total_loss/len(loader):.4f}")

# 4) Extract features
model.eval()
features = []
with torch.no_grad():
    for imgs, _ in DataLoader(train_subset, batch_size=256):
        imgs = imgs.to(device)
        _, feats = model(imgs)
        features.append(feats.cpu().numpy())
X_feat = np.vstack(features)  # Shape (n, 16)
n, m = X_feat.shape

# 5) Get final-layer weight vector
y_vec = model.out.weight.detach().cpu().numpy().reshape(-1)

# 6) Quantize to integers
scale = 1000
X_int = np.round(X_feat * scale).astype(int)
y_int = np.round(y_vec * scale).astype(int)

# 7) Run FeDDHMultiClient
tag = b"pytorch-cnn-fe"
fe = FeDDHMultiClient.generate(n, m)

# Encrypt each feature vector
cs = [
    FeDDHMultiClient.encrypt(
        X_int[i].tolist(),
        tag,
        fe.get_enc_key(i)
    )
    for i in range(n)
]

# Create a matrix by repeating y_int n times to match expected shape (n, m)
y_mat = np.tile(y_int, (n, 1))  # Shape: (n, m) = (12665, 16)

# Generate secret key for decryption
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
print("Decrypted Σ⟨xᵢ, y⟩ =", result)
print("Expected Σ⟨xᵢ, y⟩ =", expected_result)