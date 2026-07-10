# Phish Aegis

Phish Aegis is an intelligent multi-channel phishing detection system that detects phishing attacks across URLs, emails, SMS messages, and image-based content.

Phishing attacks represent a persistent and evolving cybersecurity threat in modern digital communication systems, targeting users through emails, SMS messages, malicious URLs, and image-based content. Traditional detection mechanisms based on static rules and blacklist repositories are often insufficient to detect newly emerging and zero-hour phishing attacks.

This project integrates Machine Learning (ML), Deep Learning (DL), and Optical Character Recognition (OCR) into a unified framework. Each data source is processed through a dedicated detection pipeline tailored to its characteristics.

## Detection Modules

* URL phishing detection using Gradient Boosting Classifier.
* Email phishing detection using GRU.
* SMS smishing detection using BiLSTM.
* Image-based phishing detection using OCR.

## Results

| Module | Model                        | Performance                                                       |
| ------ | ---------------------------- | ----------------------------------------------------------------- |
| URL    | Gradient Boosting Classifier | Accuracy: 97.4%, Precision: 98.6%, Recall: 99.4%, F1-score: 97.7% |
| Email  | GRU                          | Validation Accuracy: 97.8%, Validation Loss: 0.0700               |
| SMS    | BiLSTM                       | Validation Accuracy: 97.68%, Validation Loss: 0.0828              |

## System Components

* Web application
* Mobile application
* Browser extension
* OCR processing module
* API integration

## Technologies Used

* Python
* Flask
* Machine Learning
* Deep Learning
* OCR
* React Native / Expo
* JavaScript
* GitHub
* Hugging Face Spaces

## Authors

Graduation Project
Computer Engineering Department
University of Tripoli
