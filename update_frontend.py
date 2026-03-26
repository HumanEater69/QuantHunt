import re
with open('frontend/app.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('quanthunt-report-', 'quanthunt-report-')
text = text.replace('quanthunt-certificate-', 'quanthunt-certificate-')
text = text.replace('QuantHuntFloating', 'QuantHuntFloating')
text = text.replace('QuantHunt is ready', 'QuantHunt AI is ready')
text = text.replace('QUANTHUNT ASSISTANT', 'QUANTHUNT ASSISTANT')

with open('frontend/app.jsx', 'w', encoding='utf-8') as f:
    f.write(text)
