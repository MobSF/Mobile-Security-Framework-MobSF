from transformers import AutoModelForSequenceClassification, AutoTokenizer

import torch
import torch.nn.functional as functional
import os 


def array_to_str(dataset):

    if isinstance(dataset, (list, tuple)):
        cadena = ''
        for x in dataset:
            cadena += x + ','
    else:
        cadena = dataset
    cadena.strip()
    cadena = cadena[:-1]
    if len(cadena) == 0:
        cadena = 'Sin_permisos_definidos'

    return cadena


def validate_malware_ia(data):

    permission = list(data.keys()) if data.keys() else []
    permission = array_to_str(permission)

    model_path = os.path.join("mobsf", "StaticAnalyzer", "tools", "IA_model", "NyerAndroidMalware")
    #model_path = 'mobsf\\StaticAnalyzer\\tools\\IA_model\\NyerAndroidMalware'

    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    tokenizer = AutoTokenizer.from_pretrained(model_path)

    inputs = tokenizer(permission, return_tensors='pt', truncation=True, padding=True)


    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits

    probs = functional.softmax(logits, dim=1)


    prob_benign, prob_malware = probs[0].tolist()

    print(f'Probabilidad Benigno: {prob_benign * 100:.2f}%')
    print(f'Probabilidad Malware: {prob_malware * 100:.2f}%')

    return {'IA_MALWARE_PERCENTAGE': prob_malware}
