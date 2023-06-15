import json
import logging
import hashlib
import datetime
import spacy
from bs4 import BeautifulSoup
from elasticsearch import Elasticsearch
from fake_useragent import UserAgent
from requests import get
import pika
import urllib3
from datasketch import MinHash, MinHashLSH
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from textblob import TextBlob

RABBITMQ_HOST = 'localhost'
RABBITMQ_QUEUE_TASKS = 'tasks'
RABBITMQ_QUEUE_RESULTS = 'results'

ELASTICSEARCH_INDEX = 'my_index'
ELASTICSEARCH_DOC_TYPE = 'my_doc_type'
ELASTICSEARCH_HOST = "http://localhost:9200"

headers = {
    "User-Agent": UserAgent().random
}

logging.basicConfig(filename='logs.log', level=logging.INFO)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
date = datetime.date.today()

nlp = spacy.load("en_core_web_sm")

def connect_rabbitmq():
    credentials = pika.PlainCredentials('guest', 'guest')
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters(RABBITMQ_HOST, credentials=credentials))
        channel = connection.channel()
        channel.queue_declare(queue=RABBITMQ_QUEUE_TASKS)
        channel.queue_declare(queue=RABBITMQ_QUEUE_RESULTS, auto_delete=False)
        return connection, channel
    except Exception as e:
        logging.error(f"Failed to connect to RabbitMQ: {e}")
        raise e

def connect_elasticsearch(ELASTICSEARCH_HOST):
    try:
        es = Elasticsearch([ELASTICSEARCH_HOST], basic_auth=("elastic", "nuMZ7JRTtJpQYSORhI=n"))
        return es
    except Exception as e:
        logging.error(f"Failed to connect to Elasticsearch: {e}")
        raise e

def compute_minhash(text):
    shingles = set()
    words = text.split()
    for i in range(len(words) - 2): 
        shingle = ' '.join(words[i:i+3])
        shingles.add(shingle)
    minhash = MinHash(num_perm=128)
    for shingle in shingles:
        minhash.update(shingle.encode('utf-8'))
    return minhash

def find_duplicate_texts(es, text):
    minhash = compute_minhash(text)
    lsh = MinHashLSH(threshold=0.5, num_perm=128)
    duplicates = []
    for doc in es.search(index=ELASTICSEARCH_INDEX, body={"query": {"match_all": {}}})['hits']['hits']:
        if '_source' in doc and 'info_threats' in doc['_source']:
            doc_text = doc['_source']['info_threats']
            doc_minhash = compute_minhash(doc_text)
            if minhash.jaccard(doc_minhash) >= 0.5:
                duplicates.append(doc_text)
    return duplicates

def cluster_texts(texts):
    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(texts)
    
    kmeans = KMeans(n_clusters=3, random_state=0)
    kmeans.fit(X)
    
    clusters = kmeans.labels_
    return clusters

def extract_entities(text):
    doc = nlp(text)
    entities = []
    for entity in doc.ents:
        entities.append((entity.text, entity.label_))
    return entities

def get_sentiment(text):
    blob = TextBlob(text)
    sentiment = blob.sentiment.polarity
    return sentiment

import time

def parse_site(rabbitmq_channel, es):
    texts = []

    for i in range(1, 4):
        r = get(url=f"https://bdu.fstec.ru/threat?size=100&page={i}", headers=headers, verify=False)
        urllib3.disable_warnings()
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            table = soup.find('table', {"class": "table table-striped table-threats"})
            for tr in table.find_all('tr'):
                for link in tr.find_all('a'):
                    while True:
                        r = get(url=f"https://bdu.fstec.ru/{link['href']}?viewtype=tile", headers=headers, verify=False)
                        if r.status_code == 503:
                            logging.warning(f"503 error encountered. Retrying in 5 seconds...")
                            time.sleep(5)
                            break
                        elif r.status_code == 403:
                            logging.warning(f"403 error encountered. Use a proxy server")
                            break
                        elif r.status_code == 404:
                            logging.warning(f"404 error encountered. Page not found")
                            break
                        elif not (200 <= r.status_code <= 299):
                            logging.error(f'Error at {r.url}, status code: {r.status_code}')
                        break 

                    soup = BeautifulSoup(r.text, 'html.parser')
                    threats = soup.find('div', {"class": "col-sm-11"}).find('h4').text.strip()
                    threats_text = soup.find('div', {"class": "panel-body"}).text.strip().replace('\r', '').replace('\n', '')
                    id = hashlib.sha256(f"{date}{threats}".encode('utf-8')).hexdigest()
                    logging.info(f'Parsed {r.url} with id {id}')

                    entities = extract_entities(threats_text)
                    message = {'threats': threats, 'info_threats': threats_text, 'entities': entities, 'id': id, 'date': date}

                    duplicates = find_duplicate_texts(es, threats_text)
                    if duplicates:
                        message['duplicates'] = duplicates

                    sentiment = get_sentiment(threats_text)
                    message['sentiment'] = sentiment

                    rabbitmq_channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_TASKS, body=json.dumps(message))
                    es.index(index=ELASTICSEARCH_INDEX, doc_type=ELASTICSEARCH_DOC_TYPE, id=id, body=message)

                    texts.append(threats_text)

    clusters = cluster_texts(texts)
    for i, text in enumerate(texts):
        message = json.loads(rabbitmq_channel.basic_get(RABBITMQ_QUEUE_TASKS)[2])
        message['cluster'] = clusters[i]
        rabbitmq_channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_RESULTS, body=json.dumps(message))

def consume_results(rabbitmq_channel, es):
    def callback(ch, method, properties, body):
        message = json.loads(body)
        threats = message['threats']
        threats_text = message['info_threats']
        id = message['id']
        result = {'threats': threats, 'info_threats': threats_text, 'id': id, 'date': date}
        es.update(index=ELASTICSEARCH_INDEX, doc_type=ELASTICSEARCH_DOC_TYPE, id=id, body={'doc': result})
        ch.basic_ack(delivery_tag=method.delivery_tag)

    rabbitmq_channel.basic_qos(prefetch_count=1)
    rabbitmq_channel.basic_consume(queue=RABBITMQ_QUEUE_RESULTS, on_message_callback=callback)
    rabbitmq_channel.start_consuming()

def main():
    connection, channel = connect_rabbitmq()
    es = connect_elasticsearch(ELASTICSEARCH_HOST)
    parse_site(channel, es)
    consume_results(channel, es)
    connection.close()

if __name__ == "__main__":
    main()
