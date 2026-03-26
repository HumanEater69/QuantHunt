import re

files = ['backend/kb_generator.py', 'backend/offline_kb.json', 'backend/main.py']
for file in files:
    with open(file, 'r', encoding='utf-8') as f:
        text = f.read()

    text = text.replace('QuantHunt', 'QuantHunt AI')

    with open(file, 'w', encoding='utf-8') as f:
        f.write(text)
