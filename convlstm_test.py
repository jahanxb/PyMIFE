import torch
import torch.nn as nn
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from torch.utils.data import DataLoader, Dataset
import matplotlib.pyplot as plt

# ------------ Config ------------
GRID_SIZE = (15, 15)  # Grid shape to reshape N=228 into
SEQ_LEN = 12          # Input timesteps
PRED_LEN = 1          # Predict 1 step ahead
BATCH_SIZE = 64
EPOCHS = 20
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ------------ Data Prep ------------
class PeMSDataset(Dataset):
    def __init__(self, data, seq_len, pred_len):
        self.data = data
        self.seq_len = seq_len
        self.pred_len = pred_len

    def __len__(self):
        return len(self.data) - self.seq_len - self.pred_len

    def __getitem__(self, idx):
        x = self.data[idx:idx+self.seq_len]
        y = self.data[idx+self.seq_len:idx+self.seq_len+self.pred_len]
        return torch.tensor(x, dtype=torch.float32), torch.tensor(y, dtype=torch.float32)

def reshape_to_grid(data, grid_shape):
    T, N, _ = data.shape
    flat_size = grid_shape[0] * grid_shape[1]
    
    if N > flat_size:
        raise ValueError(f"Grid too small. {flat_size} < {N}")
    
    grid_data = np.zeros((T, *grid_shape, 1))
    flat = np.zeros(flat_size)
    flat[:N] = 1  # mask for sensor positions
    indices = np.where(flat.reshape(grid_shape) == 1)

    for t in range(T):
        grid = np.zeros(grid_shape)
        grid[indices] = data[t, :, 0]
        grid_data[t, :, :, 0] = grid
    return grid_data


# ------------ Model ------------

class ConvLSTMCell(nn.Module):
    def __init__(self, input_dim, hidden_dim, kernel_size, bias=True):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim

        padding = kernel_size[0] // 2, kernel_size[1] // 2
        self.conv = nn.Conv2d(
            in_channels=self.input_dim + self.hidden_dim,
            out_channels=4 * self.hidden_dim,
            kernel_size=kernel_size,
            padding=padding,
            bias=bias,
        )

    def forward(self, x, cur_state):
        h_cur, c_cur = cur_state
        combined = torch.cat([x, h_cur], dim=1)  # concatenate along channel axis
        combined_conv = self.conv(combined)
        cc_i, cc_f, cc_o, cc_g = torch.split(combined_conv, self.hidden_dim, dim=1)
        i = torch.sigmoid(cc_i)
        f = torch.sigmoid(cc_f)
        o = torch.sigmoid(cc_o)
        g = torch.tanh(cc_g)

        c_next = f * c_cur + i * g
        h_next = o * torch.tanh(c_next)
        return h_next, c_next

    def init_hidden(self, batch_size, spatial_size):
        height, width = spatial_size
        return (
            torch.zeros(batch_size, self.hidden_dim, height, width, device=self.conv.weight.device),
            torch.zeros(batch_size, self.hidden_dim, height, width, device=self.conv.weight.device),
        )

class ConvLSTM(nn.Module):
    def __init__(self, input_dim, hidden_dims, kernel_size, num_layers=1, batch_first=True, bias=True):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dims = hidden_dims if isinstance(hidden_dims, list) else [hidden_dims]
        self.kernel_size = kernel_size
        self.num_layers = num_layers
        self.batch_first = batch_first

        self.cell_list = nn.ModuleList()

        for i in range(self.num_layers):
            cur_input_dim = self.input_dim if i == 0 else self.hidden_dims[i - 1]
            self.cell_list.append(
                ConvLSTMCell(
                    input_dim=cur_input_dim,
                    hidden_dim=self.hidden_dims[i],
                    kernel_size=self.kernel_size,
                    bias=bias,
                )
            )

    def forward(self, input_tensor):
        # input_tensor: [B, T, C, H, W] if batch_first=True
        if not self.batch_first:
            input_tensor = input_tensor.permute(1, 0, 2, 3, 4)

        b, t, c, h, w = input_tensor.size()
        h_states = []
        c_states = []

        for layer_idx in range(self.num_layers):
            h, c = self.cell_list[layer_idx].init_hidden(b, (h, w))
            h_states.append(h)
            c_states.append(c)

        layer_output = input_tensor
        outputs = []

        for t_step in range(t):
            x = layer_output[:, t_step]
            for layer_idx in range(self.num_layers):
                h, c = self.cell_list[layer_idx](x, (h_states[layer_idx], c_states[layer_idx]))
                h_states[layer_idx], c_states[layer_idx] = h, c
                x = h
            outputs.append(h)

        outputs = torch.stack(outputs, dim=1)  # [B, T, C, H, W]
        return outputs, (h_states, c_states)


class ConvLSTMBlock(nn.Module):
    def __init__(self, input_channels, hidden_channels, kernel_size):
        super().__init__()
        self.convlstm = nn.LSTM(input_size=input_channels,
                                hidden_size=hidden_channels,
                                num_layers=1,
                                batch_first=True)

    def forward(self, x):
        # x: [batch, time, height, width, channels]
        b, t, h, w, c = x.size()
        x = x = x.reshape(b, t, -1)

        output, _ = self.convlstm(x)
        return output[:, -1].view(b, h, w, -1)

class ConvLSTM(nn.Module):
    def __init__(self, input_dim, hidden_dims, kernel_size, num_layers=1, batch_first=True, bias=True):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dims = hidden_dims if isinstance(hidden_dims, list) else [hidden_dims]
        self.kernel_size = kernel_size
        self.num_layers = num_layers
        self.batch_first = batch_first

        self.cell_list = nn.ModuleList()

        for i in range(self.num_layers):
            cur_input_dim = self.input_dim if i == 0 else self.hidden_dims[i - 1]
            self.cell_list.append(
                ConvLSTMCell(
                    input_dim=cur_input_dim,
                    hidden_dim=self.hidden_dims[i],
                    kernel_size=self.kernel_size,
                    bias=bias,
                )
            )

    def forward(self, input_tensor):
        # input_tensor: [B, T, C, H, W] if batch_first=True
        if not self.batch_first:
            input_tensor = input_tensor.permute(1, 0, 2, 3, 4)

        b, t, c, h, w = input_tensor.size()
        h_states = []
        c_states = []

        for layer_idx in range(self.num_layers):
            h, c = self.cell_list[layer_idx].init_hidden(b, (h, w))
            h_states.append(h)
            c_states.append(c)

        layer_output = input_tensor
        outputs = []

        for t_step in range(t):
            x = layer_output[:, t_step]
            for layer_idx in range(self.num_layers):
                h, c = self.cell_list[layer_idx](x, (h_states[layer_idx], c_states[layer_idx]))
                h_states[layer_idx], c_states[layer_idx] = h, c
                x = h
            outputs.append(h)

        outputs = torch.stack(outputs, dim=1)  # [B, T, C, H, W]
        return outputs, (h_states, c_states)


class ConvLSTMWrapper(nn.Module):
    def __init__(self, input_channels=1, hidden_channels=64, num_layers=1):
        super().__init__()
        self.convlstm = ConvLSTM(input_dim=input_channels,
                                 hidden_dims=hidden_channels,
                                 kernel_size=(3, 3),
                                 num_layers=num_layers,
                                 batch_first=True)

        self.decoder = nn.Conv2d(hidden_channels, 1, kernel_size=3, padding=1)

    def forward(self, x):
        # x: [B, T, H, W, C] → [B, T, C, H, W]
        x = x.permute(0, 1, 4, 2, 3)
        output, (last_h, _) = self.convlstm(x)
        last_output = last_h[-1]  # shape [B, hidden, H, W]
        out = self.decoder(last_output)  # shape [B, 1, H, W]
        return out.unsqueeze(-1).permute(0, 2, 3, 4, 1)  # [B, H, W, 1, 1]



# ------------ Main Script ------------
# Load dataset
data = np.load("pems07.npz")['data']  # shape [T, N, 1]


# Automatically find a grid size that's square-ish
import math
num_sensors = data.shape[1]
grid_h = int(math.floor(math.sqrt(num_sensors)))
grid_w = int(math.ceil(num_sensors / grid_h))
GRID_SIZE = (grid_h, grid_w)  # e.g., (29, 31)



scaler = MinMaxScaler()
data = scaler.fit_transform(data.reshape(-1, data.shape[1])).reshape(data.shape)

# Reshape into grid
grid_data = reshape_to_grid(data, GRID_SIZE)  # shape [T, H, W, 1]

# Create sequences
dataset = PeMSDataset(grid_data, SEQ_LEN, PRED_LEN)
train_size = int(0.8 * len(dataset))
train_data, test_data = torch.utils.data.random_split(dataset, [train_size, len(dataset) - train_size])
train_loader = DataLoader(train_data, batch_size=BATCH_SIZE, shuffle=True)
test_loader = DataLoader(test_data, batch_size=BATCH_SIZE, shuffle=False)

# Model setup
model = ConvLSTMWrapper().to(DEVICE)
criterion = nn.MSELoss()
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

print('Model:',model)

# Training loop
for epoch in range(EPOCHS):
    model.train()
    losses = []
    for x, y in train_loader:
        x, y = x.to(DEVICE), y.to(DEVICE)
        output = model(x)
        loss = criterion(output.squeeze(), y.squeeze())
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        losses.append(loss.item())
    print(f"Epoch {epoch+1}/{EPOCHS} - Loss: {np.mean(losses):.4f}")

# Evaluation
model.eval()
with torch.no_grad():
    for x, y in test_loader:
        x, y = x.to(DEVICE), y.to(DEVICE)
        preds = model(x)
        preds = preds.cpu().numpy()
        y = y.cpu().numpy()
        break  # only show one batch
print('Model after evaluation...')
print(model)
# Visualize one prediction
plt.imshow(preds[0, :, :, 0], cmap='hot')
plt.title("Predicted Traffic Flow (1 step ahead)")
plt.colorbar()
plt.show()
