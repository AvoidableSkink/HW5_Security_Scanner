from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def index():
    query_one_input = request.form['search']
    return render_template('task2.html')









if __name__ == '__main__':
    app.run(debug=True)