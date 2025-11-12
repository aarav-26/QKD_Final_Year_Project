import torch
import torch.nn as nn
import torch.optim as optim
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# ✅ Config
DATA_FILE = "ARP_MitM_dataset.csv"
LABEL_FILE = "ARP_MitM_labels.csv"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
EPOCHS = 10
BATCH_SIZE = 512

print("📥 Loading dataset...")
X = pd.read_csv(DATA_FILE, header=None)
y = pd.read_csv(LABEL_FILE)
y = y.iloc[:, 1]  # Extract label column (0 = benign, 1 = malicious)

print("🔄 Preprocessing...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

X_train = torch.tensor(X_train, dtype=torch.float32).to(DEVICE)
y_train = torch.tensor(y_train.values, dtype=torch.long).to(DEVICE)
X_test = torch.tensor(X_test, dtype=torch.float32).to(DEVICE)
y_test = torch.tensor(y_test.values, dtype=torch.long).to(DEVICE)

train_dataset = torch.utils.data.TensorDataset(X_train, y_train)
train_loader = torch.utils.data.DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)

# 🧠 Model Definition
class IDSNet(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.model = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 2)  # Output: 2 classes
        )

    def forward(self, x):
        return self.model(x)

model = IDSNet(input_dim=X.shape[1]).to(DEVICE)
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)

print("🚀 Training...")
for epoch in range(EPOCHS):
    model.train()
    total_loss = 0
    for batch_X, batch_y in train_loader:
        optimizer.zero_grad()
        outputs = model(batch_X)
        loss = criterion(outputs, batch_y)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()

    print(f"Epoch {epoch+1}/{EPOCHS} - Loss: {total_loss:.4f}")

print("💾 Saving model to ids_model.pt")
torch.save({
    'model_state_dict': model.state_dict(),
    'scaler': scaler
}, "ids_model.pt")

print("✅ Training complete!")
