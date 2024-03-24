import xml.etree.ElementTree as ET  # Importa o módulo ElementTree para análise de XML
import csv  # Importa o módulo csv para manipulação de arquivos CSV
from googletrans import Translator  # Importa o tradutor do Google Translate

def translate_text(texts):
    try:
        translator = Translator()  # Inicializa o tradutor do Google Translate
        # Traduz os textos para o português
        translated_texts = [translator.translate(text, src='auto', dest='pt').text for text in texts]
    except Exception as e:
        print(f"Erro durante a tradução: {e}")  # Exibe uma mensagem de erro se ocorrer algum problema durante a tradução
        translated_texts = texts  # Se ocorrer um erro, mantenha os textos originais
    return translated_texts

def parse_xml(xml_file):
    tree = ET.parse(xml_file)  # Faz o parse do arquivo XML
    root = tree.getroot()  # Obtém o elemento raiz do XML

    print("Script Iniciado")  # Exibe uma mensagem indicando que o script foi iniciado

    vulnerabilities = []  # Lista para armazenar as vulnerabilidades

    for ip_element in root.findall('.//IP'):
        ip = ip_element.get('value')  # Obtém o valor do atributo 'value' do elemento 'IP'

        # Processa os elementos 'VULN' dentro de cada elemento 'IP'
        for vuln_element in ip_element.findall('.//VULN'):
            severity = int(vuln_element.get('severity'))  # Obtém a gravidade da vulnerabilidade como um inteiro
            threat = vuln_element.find('.//TITLE').text.strip()  # Obtém o título da vulnerabilidade
            impact = vuln_element.find('.//CONSEQUENCE').text.strip() if vuln_element.find('.//CONSEQUENCE') is not None else ''  # Obtém o impacto da vulnerabilidade
            solution = vuln_element.find('.//SOLUTION').text.strip() if vuln_element.find('.//SOLUTION') is not None else ''  # Obtém a solução para a vulnerabilidade

            if severity >= 2:
                # Traduz os campos 'IMPACT' e 'Solution'
                translated_impact, translated_solution = translate_text([impact, solution])
                vulnerabilities.append({
                    'IP': ip,
                    'Severity': severity,
                    'THREAT': threat,
                    'IMPACT': translated_impact,
                    'Solution': translated_solution
                })

        # Processa os elementos 'CAT' dentro de cada elemento 'IP'
        for cat_element in ip_element.findall('.//CAT'):
            cat_value = cat_element.get('value')  # Obtém o valor do atributo 'value' do elemento 'CAT'

            # Processa os elementos 'INFO' dentro de cada elemento 'CAT'
            for info_element in cat_element.findall('.//INFO'):
                severity = int(info_element.get('severity'))  # Obtém a gravidade da vulnerabilidade como um inteiro

                if severity >= 2:
                    # Obtém e traduz a diagnóstico, consequência e solução da vulnerabilidade
                    diagnosis_element = info_element.find('.//DIAGNOSIS')
                    diagnosis = translate_text([diagnosis_element.text.strip()]) if diagnosis_element is not None else ''

                    consequence_element = info_element.find('.//CONSEQUENCE')
                    consequence = translate_text([consequence_element.text.strip()]) if consequence_element is not None else ''

                    solution_element = info_element.find('.//SOLUTION')
                    solution = translate_text([solution_element.text.strip()]) if solution_element is not None else ''

                    vulnerabilities.append({
                        'IP': ip,
                        'Category': cat_value,
                        'Severity': severity,
                        'THREAT': diagnosis[0] if diagnosis else '',  # Ajuste para acessar o primeiro item da lista traduzida
                        'IMPACT': consequence[0] if consequence else '',  # Ajuste para acessar o primeiro item da lista traduzida
                        'Solution': solution[0] if solution else ''  # Ajuste para acessar o primeiro item da lista traduzida
                    })

            # Processa os elementos 'SERVICE' dentro de cada elemento 'CAT'
            for service_element in cat_element.findall('.//SERVICE'):
                severity = int(service_element.get('severity'))  # Obtém a gravidade da vulnerabilidade como um inteiro

                if severity >= 2:
                    # Obtém e traduz a diagnóstico, consequência e solução da vulnerabilidade
                    diagnosis_element = service_element.find('.//DIAGNOSIS')
                    diagnosis = translate_text([diagnosis_element.text.strip()]) if diagnosis_element is not None else ''

                    consequence_element = service_element.find('.//CONSEQUENCE')
                    consequence = translate_text([consequence_element.text.strip()]) if consequence_element is not None else ''

                    solution_element = service_element.find('.//SOLUTION')
                    solution = translate_text([solution_element.text.strip()]) if solution_element is not None else ''

                    vulnerabilities.append({
                        'IP': ip,
                        'Category': cat_value,
                        'Severity': severity,
                        'THREAT': diagnosis[0] if diagnosis else '',  # Ajuste para acessar o primeiro item da lista traduzida
                        'IMPACT': consequence[0] if consequence else '',  # Ajuste para acessar o primeiro item da lista traduzida
                        'Solution': solution[0] if solution else ''  # Ajuste para acessar o primeiro item da lista traduzida
                    })

    return vulnerabilities

def write_to_csv(vulnerabilities, output_file):
    with open(output_file, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['IP', 'Category', 'Severity', 'THREAT', 'IMPACT', 'Solution'], delimiter=';')
        writer.writeheader()  # Escreve o cabeçalho no arquivo CSV
        writer.writerows(vulnerabilities)  # Escreve as vulnerabilidades no arquivo CSV

if __name__ == "__main__":
    xml_file = "Hagana_CTH_0-60.xml"  # Nome do arquivo XML de entrada
    output_file = "output_vulnerabilities.csv"  # Nome do arquivo CSV de saída

    vulnerabilities = parse_xml(xml_file)  # Analisa o arquivo XML em busca de vulnerabilidades
    write_to_csv(vulnerabilities, output_file)  # Escreve as vulnerabilidades traduzidas no arquivo CSV de saída

print("Script Finalizado")  # Exibe uma mensagem indicando que o script foi finalizado
