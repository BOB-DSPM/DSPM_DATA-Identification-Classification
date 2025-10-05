# classifiers/topic_model.py
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

LABELS = ["SENSITIVE_BELIEF","SENSITIVE_POLITICAL","SENSITIVE_UNION","SENSITIVE_HEALTH","SENSITIVE_SEX_LIFE"]

class TopicClassifier:
    def __init__(self, path):
        self.tokenizer = AutoTokenizer.from_pretrained(path)
        self.model = AutoModelForSequenceClassification.from_pretrained(path)
        self.model.eval()

    def predict(self, text: str) -> dict:
        with torch.no_grad():
            enc = self.tokenizer(text, truncation=True, max_length=256, return_tensors="pt")
            logits = self.model(**enc).logits[0]
            probs = torch.sigmoid(logits).tolist()
        return dict(zip(LABELS, probs))
