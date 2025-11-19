# recognizers/hf_ner_recognizer.py
from typing import List
import os
from presidio_analyzer import EntityRecognizer, RecognizerResult

HF_MODEL = os.getenv(
    "HF_NER_MODEL",
    "alphagyuu/Korean-PII-Masking-BertForTokenClassification",
)

class HfNerRecognizer(EntityRecognizer):
    def __init__(self):
        # Presidio 2.2.x: __init__는 두 인자만 허용
        super().__init__(supported_entities=["HF_NER"], supported_language="ko")
        # 추가 언어는 인스턴스 속성으로 직접 부여
        self.supported_languages = ["ko", "en"]

        self.pipe = None
        try:
            from transformers import pipeline
            self.pipe = pipeline(
                "token-classification",
                model=HF_MODEL,
                aggregation_strategy="simple",
            )
        except Exception as e:
            self._err = e
            self.pipe = None

    def analyze(self, text: str, entities: List[str], nlp_artifacts=None):
        if not self.pipe or not text:
            return []
        outs: List[RecognizerResult] = []
        try:
            preds = self.pipe(text)
            for p in preds:
                start = int(p.get("start", 0))
                end   = int(p.get("end", 0))
                score = float(p.get("score", 0.0))
                label = p.get("entity_group") or p.get("entity")
                rr = RecognizerResult(entity_type="HF_NER", start=start, end=end, score=score)
                rr.analysis_explanation = {"label": label}
                outs.append(rr)
        except Exception:
            return []
        return outs
