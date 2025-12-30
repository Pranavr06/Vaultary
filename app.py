from flask import Flask, render_template, request, jsonify
from zxcvbn import zxcvbn

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check_password', methods=['POST'])
def check_password():
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'No password provided'}), 400

    # This is where the magic happens (zxcvbn analysis)
    results = zxcvbn(password)
    
    response = {
        'score': results['score'],  # 0 to 4 (0=weak, 4=strong)
        'crack_time': results['crack_times_display']['offline_slow_hashing_1e4_per_second'],
        'feedback': results['feedback'],
        'guesses': results['guesses']
    }
    
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True)