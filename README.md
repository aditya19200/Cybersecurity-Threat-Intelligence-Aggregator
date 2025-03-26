# 🛡️ Cybersecurity Threat Intelligence Aggregator

## Project Overview
A comprehensive web application for aggregating, analyzing, and visualizing cybersecurity threat intelligence from multiple open-source feeds.

## 🌟 Key Features
- Threat data aggregation from multiple sources
- Machine learning-based threat classification
- Interactive threat visualization dashboard
- Detailed threat reporting

## 🛠 Tech Stack
- **Backend**: Python (Flask)
- **Frontend**: React.js
- **Machine Learning**: scikit-learn
- **Data Visualization**: Plotly, Recharts

## 📦 Prerequisites
- Python 3.8+
- Node.js 14+
- pip
- npm

## 🚀 Installation

### Backend Setup
1. Clone the repository
2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

3. Install Python dependencies
```bash
pip install -r requirements.txt
```

4. Run the Flask backend
```bash
python app.py
```

### Frontend Setup
1. Navigate to frontend directory
```bash
cd frontend
npm install
npm start
```

## 📝 Configuration
- Modify `threat_sources` in `app.py` to add/remove threat intelligence sources
- Adjust machine learning training data in `app.py`

## 🔍 Usage
- Backend runs on `http://localhost:5000`
- Frontend runs on `http://localhost:3000`
- Access the threat intelligence dashboard through the web interface

## 🧪 Testing
- Run backend tests: `python -m unittest discover tests`
- Run frontend tests: `npm test`

## 📄 License
This project is licensed under the MIT License.

##screenshort
<img width="294" alt="image" src="https://github.com/user-attachments/assets/a98aca2e-5e7f-4b9d-8dd7-82b689741778" />
<img width="309" alt="image" src="https://github.com/user-attachments/assets/cc2c5207-987e-4b99-8310-758e9161577a" />

