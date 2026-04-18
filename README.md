# 🛡️ Automated Phishing Website Detection using Machine Learning

🔗 **GitHub Repo:** https://github.com/alimusharraf/PhishGuard

---

## 📌 Overview

This project presents an **automated phishing website detection system** using Machine Learning. It analyzes URLs and classifies them as **Phishing** or **Legitimate** based on extracted features.

The system uses an **XGBoost model** trained on URL-based and structural features to provide **real-time predictions** through a Flask web application.

---

## 🚀 Features

* 🔍 Detects phishing websites in real-time
* 🤖 Uses Machine Learning (**XGBoost**)
* 🌐 Web interface built with Flask
* 📊 Extracts 40+ URL-based features
* ⚡ Fast and lightweight prediction
* 📈 Displays prediction with confidence score

---

## 🧠 Tech Stack

* Python
* Flask
* Pandas
* Scikit-learn
* XGBoost
* HTML/CSS (Frontend)

---

## 📂 Project Structure

```
project/
│── app.py
│── XGBoost_model.pkl
│── label_encoder.pkl
│── templates/
│     └── index.html
│── requirements.txt
│── README.md
```

---

## ⚙️ Installation

### 1️⃣ Clone the repository

```
git clone https://github.com/alimusharraf/<your-project-name>.git
cd <your-project-name>
```

### 2️⃣ Create virtual environment (recommended)

```
python -m venv myenv
myenv\Scripts\activate   # Windows
```

### 3️⃣ Install dependencies

```
pip install -r requirements.txt
```

---

## ▶️ Run the Application

```
python app.py
```

Then open your browser and go to:

```
http://127.0.0.1:5000/
```

---

## 🧪 How it Works

1. User enters a URL

2. System extracts multiple features:

   * URL length
   * Number of special characters
   * Presence of suspicious keywords
   * Domain properties
   * Entropy & structural patterns

3. Features are passed to the trained **XGBoost model**

4. Model predicts:

   * ✅ Legitimate
   * ❌ Phishing

5. Result + confidence score is displayed

---

## 📊 Model Details

* Algorithm: **XGBoost**
* Type: Supervised Learning
* Input: URL-based features
* Output: Phishing / Legitimate classification

---

## ⚠️ Limitations

* Depends on training data quality
* May not detect highly sophisticated phishing attacks
* Does not analyze full webpage content (only URL features)

---

## 🔮 Future Improvements

* Add Deep Learning models (LSTM / CNN)
* Browser extension integration
* Real-time dataset updates
* Explainable AI (XAI) support
* Email phishing detection

---

## 👨‍💻 Authors

* Musharraf Ali
* Akif Ahmed Shariff
* Lucky Sharma
* Mohammed Junaid

---

## 📜 License

This project is for educational purposes.

---

## 🙌 Acknowledgement

Guided by **Mrs. Shweta S**, Assistant Professor, Department of CSE.

---

## ⭐ If you like this project

Give it a ⭐ on GitHub!
