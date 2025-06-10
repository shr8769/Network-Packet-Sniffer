
# Network Packet Sniffer

A real-time network packet sniffer and analyzer with a web-based dashboard. Capture, visualize, and analyze network traffic with ease. Designed for local use with optional remote access via ngrok.

---

## ✨ Features

- **Real-Time Packet Capture:** Start and stop live packet capturing with a simple interface.
- **Protocol Analysis:** Automatically detects and categorizes traffic by protocol (HTTP, HTTPS, TCP, UDP, ICMP).
- **Interactive Dashboard:** Visualize total packets, average size, protocol distribution, and energy consumption in real time.
- **Data Visualization:**  
  - **Protocol Distribution:** Donut chart showing the breakdown of protocols.
  - **Packet Size Distribution:** Bar chart displaying packet sizes.
  - **Energy Consumption:** Line chart tracking estimated energy usage over time.
- **Anomaly Detection:** Highlights unusual or suspicious traffic patterns.
- **Remote Access:** Share your dashboard securely over the internet using ngrok.

---

## 🖼️ Screenshots

![image](https://github.com/user-attachments/assets/684b6570-2fe7-46f0-9cf1-000cb202688e)


![image](https://github.com/user-attachments/assets/71f80cf3-9754-46ed-b166-90b26971433b)


![image](https://github.com/user-attachments/assets/b639b3e1-3dce-44b6-baf9-cab36cdfda38)


![image](https://github.com/user-attachments/assets/037ada54-35ff-4a46-a629-8d5332d0e42a)

![image](https://github.com/user-attachments/assets/efb34c2c-16c0-4da3-9498-7eda3cc70f3d)



---
🛠️ Technology Stack
Backend: Python (with Flask or similar framework for API endpoints)

Frontend:

->HTML, CSS, and JavaScript for the web interface

->Bootstrap for responsive layout and styling

->jQuery for DOM manipulation and AJAX requests

->Chart.js for data visualization (protocol, packet size, and energy charts)

->Optional Remote Access: ngrok for exposing your local server to the internet

Note:
This project currently uses a traditional web stack (HTML/CSS/JS) for the dashboard. React is not used, but you can migrate or add a React frontend in the future if you prefer a modern SPA (Single Page Application) approach
---

## 🚀 Getting Started

### Prerequisites

- **Python 3.8+**
- **pip** (Python package manager)
- **Git** (version control)
- **ngrok** (for remote access, optional)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/shr8769/Network-Packet-Sniffer.git
   cd Network-Packet-Sniffer
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python app/main.py
   ```
   *(Replace with your actual start command if different.)*

4. **Access the dashboard:**
   - Open your browser and go to:  
     ```
     http://localhost:5000
     ```
   - Use the dashboard to start packet capture and view analytics.

---

## 🌍 Remote Access with ngrok

Want to share your dashboard? Use ngrok to expose your local server securely:

1. **Start your application as above.**
2. **Open a new terminal and run:**
   ```bash
   ngrok http 5000
   ```
3. **Copy the public URL provided by ngrok and share it with others.**

---

## 📝 Guide for Contributors

1. **Fork the repository.**
2. **Clone your fork and create a new branch:**
   ```bash
   git checkout -b feature/your-feature
   ```
3. **Make your changes and commit them:**
   ```bash
   git add .
   git commit -m "Your commit message"
   ```
4. **Push your branch to GitHub:**
   ```bash
   git push origin feature/your-feature
   ```
5. **Open a pull request from your branch to the main repository.**

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

