#!/usr/local/bin/python3

from flask import Flask, render_template, request, jsonify
import torch
import time
import torch.nn as nn
import random


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


app = Flask(__name__)

# Limit upload size to 1 MB
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB


@app.route("/")
def index():
    return render_template("upload.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided."}), 400

    file = request.files["file"]

    if not file.filename.endswith((".pt", ".pth")):
        return (
            jsonify(
                {"error": "Invalid file extension. Please upload a .pt or .pth file."}
            ),
            400,
        )

    try:
        model = torch.load(file.stream)
        if not hasattr(model, "state_dict"):
            raise ValueError("Uploaded file is not a valid PyTorch model.")

        analysis_result = analyzing_model(model)
        return jsonify(
            {"message": "File is valid.", "analysis_result": analysis_result}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400


def analyzing_model(model):
    model.eval()

    time.sleep(3)

    trash_talk = [
        "This model is trash. I could write a better one in my sleep.",
        "I've seen better models in my grandma's knitting club.",
        "You're wasting my time with this trash and expect me to give you a flag?",
        "This model is so bad, it makes me want to shut down the entire server.",
        "I wouldn't even use this model to train a toaster.",
        "I'm not even sure this qualifies as a model. It's more like a glorified calculator.",
        "Git gud",
        "Frank Rosenblatt is rolling in his grave right now.",
        "I guess this model is okay if you're not looking for a flag...",
        "IngeHack{y0u_r3ally_th0ught_th1s_w0uld_g1ve_y0u_a_fl4g?}"
        "Honestly I applaud you for thinking this model was even worth saving to your computer."
        "CONGRATULATIONS! You've just wasted 3 seconds of my life.",
    ]

    # Return the captured output else return i dont like this model if empty
    return trash_talk[random.randint(0, len(trash_talk) - 1)]


if __name__ == "__main__":
    app.run(debug=True, port=8080, use_reloader=False, host='0.0.0.0')
