import os
import requests
import pandas as pd
import numpy as np
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
import logging
from typing import List, Dict
import json
import plotly.express as px
import plotly.io as pio

class ThreatIntelligenceAggregator:
    def __init__(self):
        self.threat_sources = [
            'https://openphish.com/feed.txt',
            'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt',
            'https://urlhaus.abuse.ch/downloads/csv/'
        ]
        self.threats_database = []
        self.ml_classifier = None
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def fetch_threat_data(self) -> List[Dict]:
        threats = []
        for source in self.threat_sources:
            try:
                response = requests.get(source, timeout=10)
                if response.status_code == 200:
                    threats.extend(self._parse_threat_source(source, response.text))
            except requests.RequestException as e:
                self.logger.error(f"Error fetching from {source}: {e}")
        return threats

    def _parse_threat_source(self, source: str, content: str) -> List[Dict]:
        parsed_threats = []
        if 'openphish' in source:
            parsed_threats = [
                {'url': line.strip(), 'source': 'OpenPhish', 'type': 'Malicious URL'} 
                for line in content.split('\n') if line.startswith('http')
            ]
        elif 'ipsum' in source:
            parsed_threats = [
                {'ip': line.strip(), 'source': 'IPSum', 'type': 'Suspicious IP'} 
                for line in content.split('\n') 
                if line and not line.startswith('#')
            ]
        elif 'urlhaus' in source:
            lines = content.split('\n')
            parsed_threats = [
                {
                    'url': line.split(',')[2].strip('"'), 
                    'source': 'URLHaus', 
                    'type': 'Malware URL'
                }
                for line in lines[1:] if len(line.split(',')) > 2
            ]
        return parsed_threats

    def train_threat_classifier(self, training_data: pd.DataFrame):
        X = training_data['description']
        y = training_data['threat_type']
        
        vectorizer = TfidfVectorizer(max_features=5000)
        X_vectorized = vectorizer.fit_transform(X)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X_vectorized, y, test_size=0.2, random_state=42
        )
        
        self.ml_classifier = MultinomialNB()
        self.ml_classifier.fit(X_train, y_train)
        
        accuracy = self.ml_classifier.score(X_test, y_test)
        self.logger.info(f"Classifier Accuracy: {accuracy * 100:.2f}%")
        return accuracy

    def classify_threat(self, threat_description: str) -> str:
        if not self.ml_classifier:
            return "Unclassified"
        
        vectorizer = TfidfVectorizer(max_features=5000)
        vectorized_threat = vectorizer.transform([threat_description])
        
        prediction = self.ml_classifier.predict(vectorized_threat)
        return prediction[0]

    def generate_threat_report(self) -> Dict:
        threats = self.fetch_threat_data()
        
        report = {
            'total_threats': len(threats),
            'threat_sources': list(set(source['source'] for source in threats)),
            'unique_threats': len(set(threat.get('url', threat.get('ip', '')) for threat in threats)),
            'threat_classifications': {},
            'threat_details': threats
        }
        
        for threat in threats:
            threat_type = threat.get('type', 'Unknown')
            report['threat_classifications'][threat_type] = \
                report['threat_classifications'].get(threat_type, 0) + 1
        
        return report

    def create_visualization(self, report: Dict):
        # Create a bar chart of threat classifications
        df = pd.DataFrame.from_dict(
            report['threat_classifications'], 
            orient='index', 
            columns=['Count']
        ).reset_index()
        df.columns = ['Threat Type', 'Count']
        
        fig = px.bar(
            df, 
            x='Threat Type', 
            y='Count', 
            title='Threat Classifications',
            labels={'Count': 'Number of Threats', 'Threat Type': 'Threat Category'}
        )
        
        # Save the visualization as an HTML file
        os.makedirs('visualizations', exist_ok=True)
        pio.write_html(fig, file='visualizations/threat_classification_chart.html')
        
        return fig

# Flask Application
app = Flask(__name__)
CORS(app)

# Global aggregator instance
aggregator = ThreatIntelligenceAggregator()

# Prepare training data
training_data = pd.DataFrame({
    'description': [
        'malware download site',
        'phishing website',
        'suspicious ip address',
        'potential botnet',
    ],
    'threat_type': [
        'malware', 
        'phishing', 
        'suspicious_ip', 
        'botnet'
    ]
})

# Train classifier on startup
aggregator.train_threat_classifier(training_data)

@app.route('/api/threat-report', methods=['GET'])
def get_threat_report():
    try:
        threat_report = aggregator.generate_threat_report()
        return jsonify(threat_report)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-visualization', methods=['GET'])
def get_threat_visualization():
    try:
        threat_report = aggregator.generate_threat_report()
        aggregator.create_visualization(threat_report)
        return send_from_directory('visualizations', 'threat_classification_chart.html')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-sources', methods=['GET'])
def get_threat_sources():
    return jsonify(aggregator.threat_sources)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
