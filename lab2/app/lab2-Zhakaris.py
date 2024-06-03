from flask import Flask, render_template, request, redirect, url_for, flash
import re

app = Flask(__name__)
app.secret_key = '7ed09a7b35c72d6129278b88ed3f31de6b7c66e5253d1cfe'

@app.route('/')
def index():
    return render_template('index.html', 
                           params=request.args,
                           headers=request.headers,
                           cookies=request.cookies)

@app.route('/check_phone', methods=['GET', 'POST'])
def check_phone():
    if request.method == 'POST':
        phone_number = request.form['phone_number']


        if not re.match(r'^[\d\s\-\+\(\)\.]+$', phone_number):
            flash('Недопустимый ввод. В номере телефона встречаются недопустимые символы.', 'error')
            return redirect(url_for('check_phone'))
        
        if not (phone_number.startswith('+7') or phone_number.startswith('8')):
            if len(phone_number) != 10:
                flash('Недопустимый ввод. Неверное количество цифр.', 'error')
                return redirect(url_for('check_phone'))
        elif len(phone_number) != 11:
            flash('Недопустимый ввод. Неверное количество цифр.', 'error')
            return redirect(url_for('check_phone'))

        cleaned_number = re.sub(r'\D', '', phone_number)
        formatted_number = '8-{}-{}-{}-{}'.format(cleaned_number[1:4], cleaned_number[4:7], cleaned_number[7:9], cleaned_number[9:])
        flash('Номер телефона успешно отформатирован: {}'.format(formatted_number), 'success')
        return redirect(url_for('check_phone'))

    return render_template('check_phone.html')

if __name__ == '__main__':
    app.run(debug=True)
