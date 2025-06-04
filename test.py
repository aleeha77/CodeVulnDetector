from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

model_name = "mrm8488/codebert-base-finetuned-detect-insecure-code"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name).to('cpu').eval()

test_lines = [
    'print(f"Hello, {name}!")',
    'eval(input())',
    'os.system("rm -rf /")',
    'user_input = input()',
    'exec("some code")',
]

for line in test_lines:
    inputs = tokenizer(line, return_tensors="pt", truncation=True, max_length=512).to('cpu')
    with torch.no_grad():
        outputs = model(**inputs)
    vuln_prob = torch.nn.functional.softmax(outputs.logits, dim=1)[0][1].item()
    print(f"Line: {line}\nVulnerability Score: {vuln_prob:.4f}\n")
