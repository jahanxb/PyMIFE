import torch
import torch.nn as nn
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import (
    mean_absolute_error,
    mean_squared_error,
    mean_absolute_percentage_error,
    r2_score,
    explained_variance_score,
    accuracy_score,
)
from torch.utils.data import DataLoader, Dataset, random_split
import math

# ------------ Quantization Config ------------
# Options: 'none', 'fp16', 'int8'
QUANT_MODE = 'int8'
# for int8 we need a scale factor
INT8_SCALE = 255.0

# ------------ Config ------------
SEQ_LEN    = 12
PRED_LEN   = 1
BATCH_SIZE = 64
EPOCHS     = 100
PATIENCE   = 10
MAX_LR     = 1e-3
DEVICE     = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ------------ Data Prep ------------
class PeMSDataset(Dataset):
    def __init__(self, data, seq_len, pred_len):
        # data: numpy [T,H,W,1] in float32
        self.data, self.seq_len, self.pred_len = data, seq_len, pred_len

    def __len__(self):
        return len(self.data) - self.seq_len - self.pred_len

    def __getitem__(self, idx):
        x = self.data[idx:idx+self.seq_len]        # [SEQ_LEN,H,W,1]
        y = self.data[idx+self.seq_len]            # [1,H,W,1]

        # quantize X and Y as requested
        if QUANT_MODE == 'fp16':
            x = x.astype(np.float16)
            y = y.astype(np.float16)
        elif QUANT_MODE == 'int8':
            # scale to [0,255] and cast
            x = np.clip(x, 0, 1)
            y = np.clip(y, 0, 1)
            x = (x * INT8_SCALE).round().astype(np.uint8)
            y = (y * INT8_SCALE).round().astype(np.uint8)
        # else keep float32

        # convert to torch
        if QUANT_MODE == 'int8':
            # dequantize back to float32 for model input
            x = torch.tensor(x.astype(np.float32) / INT8_SCALE)
            y = torch.tensor(y.astype(np.float32) / INT8_SCALE)
        else:
            # for both float16 or float32, cast tensor dtype
            dtype = torch.float16 if QUANT_MODE=='fp16' else torch.float32
            x = torch.tensor(x, dtype=dtype)
            y = torch.tensor(y, dtype=dtype)

        return x, y

def reshape_to_grid(data, grid_shape):
    T, N, _ = data.shape
    H, W    = grid_shape
    mask    = np.zeros(H*W, bool); mask[:N] = True
    idxs    = np.where(mask.reshape(grid_shape))
    out     = np.zeros((T,H,W,1), np.float32)
    for t in range(T):
        tmp = np.zeros((H,W), np.float32)
        tmp[idxs] = data[t,:,0]
        out[t,:,:,0] = tmp
    return out

# ------------ Model Blocks ------------
class ConvLSTMCell(nn.Module):
    def __init__(self, in_ch, hid_ch, ksize=(3,3)):
        super().__init__()
        pad = (ksize[0]//2, ksize[1]//2)
        self.conv = nn.Conv2d(in_ch + hid_ch, 4*hid_ch, ksize, padding=pad)
        self.hid_ch = hid_ch
    def forward(self, x, states):
        h, c = states
        i,f,o,g = torch.split(self.conv(torch.cat([x,h], dim=1)), self.hid_ch, dim=1)
        i, f, o = torch.sigmoid(i), torch.sigmoid(f), torch.sigmoid(o)
        g = torch.tanh(g)
        c_next = f*c + i*g
        h_next = o*torch.tanh(c_next)
        return h_next, c_next
    def init_hidden(self, B, H, W, device):
        return (torch.zeros(B,self.hid_ch,H,W,device=device),
                torch.zeros(B,self.hid_ch,H,W,device=device))

class ConvLSTM(nn.Module):
    def __init__(self, in_ch, hid_chs, ksize=(3,3)):
        super().__init__()
        layers = []
        prev = in_ch
        for h in hid_chs:
            layers.append(ConvLSTMCell(prev,h,ksize))
            prev = h
        self.layers = nn.ModuleList(layers)

    def forward(self, x):
        # x: [B,T,C,H,W]
        B,T,C,H,W = x.size()
        h = []; c = []
        for cell in self.layers:
            h0,c0 = cell.init_hidden(B,H,W,x.device)
            h.append(h0); c.append(c0)
        for t in range(T):
            xt = x[:,t]
            for i,cell in enumerate(self.layers):
                h[i],c[i] = cell(xt, (h[i],c[i]))
                xt = h[i]
        return h[-1]  # last-layer hidden

class ConvLSTMWrapper(nn.Module):
    def __init__(self, in_ch=1, hid_chs=[64,128]):
        super().__init__()
        self.encoder = ConvLSTM(in_ch, hid_chs)
        self.decoder = nn.Sequential(
            nn.Conv2d(hid_chs[-1], 64, kernel_size=3, padding=1),
            nn.BatchNorm2d(64),
            nn.ReLU(inplace=True),
            nn.Dropout2d(0.2),
            nn.Conv2d(64, 1, kernel_size=3, padding=1)
        )
        for m in self.modules():
            if isinstance(m, nn.Conv2d):
                nn.init.xavier_uniform_(m.weight)

    def forward(self, x):
        # x: [B,T,H,W,1] → [B,T,1,H,W]
        x = x.permute(0,1,4,2,3)
        h = self.encoder(x)      # [B,hidden,H,W]
        return self.decoder(h)   # [B,1,H,W]


# ------------ Main ------------
if __name__=="__main__":
    # load & normalize
    raw = np.load("pems07.npz")['data']  # [T,N,1]
    T, N, _ = raw.shape
    h = int(math.floor(math.sqrt(N)))
    w = int(math.ceil(N/h))
    GRID = (h, w)

    scaler = MinMaxScaler()
    flat   = raw.reshape(-1, N)
    norm   = scaler.fit_transform(flat).reshape(T, N, 1)

    # build grid
    grid_data = reshape_to_grid(norm, GRID)  # [T,H,W,1] float32

    # dataset & splits
    ds      = PeMSDataset(grid_data, SEQ_LEN, PRED_LEN)
    train_n = int(0.8 * len(ds))
    test_n  = len(ds) - train_n
    train_ds, test_ds = random_split(ds, [train_n, test_n])
    val_n   = int(0.1 * train_n)
    train_n -= val_n
    train_ds, val_ds = random_split(train_ds, [train_n, val_n])

    loaders = {
        'train': DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True,  drop_last=True),
        'val'  : DataLoader(val_ds,   batch_size=BATCH_SIZE, shuffle=False, drop_last=True),
        'test' : DataLoader(test_ds,  batch_size=BATCH_SIZE, shuffle=False),
    }

    model     = ConvLSTMWrapper().to(DEVICE)
    criterion = nn.MSELoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=MAX_LR, weight_decay=1e-5)
    scheduler = torch.optim.lr_scheduler.OneCycleLR(
        optimizer, max_lr=MAX_LR,
        steps_per_epoch=len(loaders['train']),
        epochs=EPOCHS,
        pct_start=0.3,
        div_factor=10,
        final_div_factor=100,
    )

    best_val, no_imp = float('inf'), 0
    for epoch in range(1, EPOCHS+1):
        model.train()
        for x, y in loaders['train']:
            # x,y will already be float16 or float32 on CPU
            x, y = x.to(DEVICE), y.to(DEVICE).squeeze(-1).unsqueeze(1)
            if QUANT_MODE == 'fp16':
                x = x.half()
                y = y.half()

            pred = model(x)
            if QUANT_MODE == 'fp16':
                # model output is half, but criterion wants float
                pred = pred.float()
                y    = y.float()
                
            loss = criterion(pred, y)
            optimizer.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()

        # validation
        model.eval()
        val_losses = []
        with torch.no_grad():
            for x, y in loaders['val']:
                x = x.to(DEVICE)
                y = y.to(DEVICE).squeeze(-1).unsqueeze(1)

                if QUANT_MODE == 'fp16':
                    x = x.half()
                    y = y.half()

                pred = model(x)
                if QUANT_MODE == 'fp16':
                    pred = pred.float()
                    y    = y.float()

                val_losses.append(criterion(pred, y).item())

        v_loss = np.mean(val_losses)
        print(f"Epoch {epoch}: Val MSE={v_loss:.4f}")
        if v_loss < best_val:
            torch.save(model.state_dict(), "best_model.pt")
            best_val, no_imp = v_loss, 0
        else:
            no_imp += 1
            if no_imp >= PATIENCE:
                print("Early stopping.")
                break

    # testing + metrics (unchanged)
    # …
    # — test & metrics —
    model.load_state_dict(torch.load("best_model.pt"))
    model.eval()

    all_preds, all_trues, all_last = [], [], []
    with torch.no_grad():
        for x,y in loaders['test']:
            x = x.to(DEVICE)
            print('\n X in Test: ',x , 
                      '\n Y in Test: ', y)
            p = model(x).cpu().numpy().reshape(-1)
            t = y.squeeze(-1).numpy().reshape(-1)
            last = x[:, -1, ..., 0].cpu().numpy().reshape(-1)

            all_preds.append(p)
            all_trues.append(t)
            all_last.append(last)

    preds = np.concatenate(all_preds)
    trues = np.concatenate(all_trues)
    lasts = np.concatenate(all_last)

    # compute metrics
    mae   = mean_absolute_error(trues, preds)
    rmse  = np.sqrt(mean_squared_error(trues, preds))
    mape  = mean_absolute_percentage_error(trues, preds) * 100
    smape = np.mean(2 * np.abs(preds - trues) /
                    (np.abs(trues) + np.abs(preds) + 1e-6)) * 100
    r2    = r2_score(trues, preds)
    evs   = explained_variance_score(trues, preds)
    dir_pred = (preds - lasts) >= 0
    dir_true = (trues - lasts) >= 0
    dir_acc  = accuracy_score(dir_true, dir_pred) * 100

    # display results
    print("\n=== Final Test Metrics ===")
    print(f"MAE       : {mae:.4f}")
    print(f"RMSE      : {rmse:.4f}")
    print(f"MAPE      : {mape:.2f}%")
    print(f"SMAPE     : {smape:.2f}%")
    print(f"R2        : {r2:.4f}")
    print(f"Explained Variance: {evs:.4f}")
    print(f"Directional Accuracy: {dir_acc:.2f}%")
