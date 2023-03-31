from flask import Flask, render_template, request, jsonify, redirect, url_for
from bson.objectid import ObjectId
from pymongo import MongoClient
from pprint import pprint
import json
import certifi
import jwt
import datetime
import hashlib

app = Flask(__name__)

client = MongoClient(f'mongodb+srv://juhyukhong:juhyukhong@juhyukhong.q0dawlr.mongodb.net/?retryWrites=true&w=majority')
db = client.sharabletodo

SECRET_KEY = 'SPARTA'

## rendering pages ##

# index.html 페이지 렌더링
@app.route('/')
def home():
    # token을 쿠키에서 불러오고,
    token = request.cookies.get('token')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_info = db.user.find_one({"id": payload['id']})
        return render_template('index.html', username=user_info['id'])
    except jwt.ExpiredSignatureError:
        # 만료된 token이라면 signin 페이지로 리디렉팅
        return render_template('index.html')
        #return redirect(url_for("signinpage", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        # 잘못된 token이라면 signin 페이지로 리디렉팅
        return render_template('index.html')
        #return redirect(url_for("signinpage", msg="로그인 정보가 존재하지 않습니다."))

# signin.html 페이지 렌더링
@app.route("/signin")
def signinpage():
    return render_template('signin.html')

# signup.html 페이지 렌더링
@app.route("/signup")
def signup():
    return render_template('signup.html')

## APIs for auth##

# 유저 회원가입
@app.route("/auth/registration", methods=["POST"])
def registration():
    try:
        # 받아온 아이디와 비밀번호를 변수에 저장하고,
        userId = request.form['userId']
        password = request.form['password']
        # 암호화 한 다음,
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        # DB에 아이디와 암호화된 비밀번호를 저장
        db.user.insert_one({'id': userId, 'pw': password_hash})
        # 저장 후 JWT 토큰을 생성해서,
        payload = {'id': userId, 'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=3600)}
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        # 성공 메시지와 토큰을 반환
        return jsonify({'result': 'success', 'token': token})
    except Exception as e:
        print(e)
        return jsonify({'result': "failed"})

# 유저 아이디 호출
@app.route("/auth/signin", methods=["GET"])
def getUserId():
    # token을 쿠키에서 불러오고,
    token = request.cookies.get('token')
    try:
        # token을 디코드해서,
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        # payload에서 userId를 찾아 반환 
        return jsonify({'result': 'success', 'userId': payload['id']})
    except jwt.ExpiredSignatureError:
        # 만료된 token이라면 signin 페이지로 리디렉팅
        return redirect(url_for("signinpage", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        # 잘못된 token이라면 signin 페이지로 리디렉팅
        #return redirect(url_for("signinpage", msg="로그인 정보가 존재하지 않습니다."))
        return jsonify({'result': 'failed', 'userId': None})

# 유저 로그인
@app.route("/auth/signin", methods=["POST"])
def signin():
    # 입력받은 값을 변수로 정의
    id = request.form['userId']
    pw = request.form['password']
    # 입력받은 비밀번호를 암호화
    pw_hash = hashlib.sha256(pw.encode('utf-8')).hexdigest()
    # 아이디, 암호화된 비밀번호로 유저를 찾기
    res = db.user.find_one({'id': id, 'pw': pw_hash})
    print(res)
    # 만약에 해당 아이디와 비밀번호가 있다면,
    if res is not None:
        # JWT 토큰을 생성
        payload = {'id': id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=3600)}
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        print(token)
        # token을 반환
        return jsonify({'result': 'success', 'token': token})
    # 해당 아이디와 비밀번호가 없다면,
    else:
        # 아이디/비밀번호 미일치 메세지와 result fail 전달
        return jsonify({'result': 'failed', 'msg': "아이디/비밀번호가 일치하지 않습니다."})

## APIs for todo##

# 입력한 todo를 받아서 DB에 저장
@app.route("/todo/save", methods=["POST"])
def saveToDo():
    # token을 쿠키에서 불러오고,
    token = request.cookies.get('token')
    # POST로 보내온 toDo 값을 변수에 저장하고,
    toDo = request.form["toDo"]
    # toDo 의 완료/미완료 상태 표시값인 status와 공유받은 아이디 값인 sharedId는 default 부여
    # status: False = 미완료, True = 완료
    status = False
    # shareId: None = 생성한 toDo, userId = 다른 유저로부터 공유받은 toDo
    sharedId = None
    try:
        # token을 디코드해서,
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        # payload에 있는 아이디와 POST로 받은 toDo, status, sharedId를 DB에 저장
        doc = {'id': payload['id'], 'toDo': toDo, 'status': status, 'sharedId': sharedId}
        db.todoList.insert_one(doc)
        # 저장한 결과를 반환
        return jsonify({'result': 'success'})
    except jwt.ExpiredSignatureError:
        # 만료된 token이라면 signin 페이지로 리디렉팅
        return redirect(url_for("signinpage", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        # 잘못된 token이라면 signin 페이지로 리디렉팅
        return redirect(url_for("signinpage", msg="로그인 정보가 존재하지 않습니다."))

# 로그인한 id가 가지고 있는 todo의 리스트를 반환
@app.route("/todo/list", methods=["GET"])
def showToDo():
    # token을 쿠키에서 불러오고,
    token = request.cookies.get('token')
    try:
        # token을 디코드해서,
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        # id값으로 모든 todo를 찾아서 리스트로 만들고,
        all_list = list(db.todoList.find({"id": payload['id']}))
        # DB의 고유 _id값은 object이므로 str으로 변환해야 jsonify가능, str으로 변환 
        for i in all_list:
            i['_id'] = str(i['_id'])
        print(all_list)
        # 반환
        return jsonify({'result': all_list})
    except jwt.ExpiredSignatureError:
        # 만료된 token이라면 signin 페이지로 리디렉팅
        return redirect(url_for("signinpage", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        # 잘못된 token이라면 signin 페이지로 리디렉팅
        return redirect(url_for("signinpage", msg="로그인 정보가 존재하지 않습니다."))

# Todo 항목 완료/미완료 토글
@app.route("/todo/toggle", methods=["POST"])
def toggle():
    # token을 쿠키에서 불러오고,
    token = request.cookies.get('token')
    try:
        # token을 디코드해서 유효한 토큰인지 확인
        _ = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        # POST로 받은 toDoId를 변수에 저장해서,
        todo_id = request.form["toDoId"]
        print(todo_id)
        # 해당 toDoId를 todoList DB에서 검색한 다음 status만 변수에 저장하고
        status = db.todoList.find_one({'_id': ObjectId(todo_id)})['status']
        # 해당 toDoId를 가진 데이터에서 status의 반대값으로 status를 업데이트 
        db.todoList.update_one({"_id": ObjectId(todo_id)}, {"$set": {'status': not(status)}})
        # 결과 반환
        return jsonify({'result': 'success'})
    except jwt.ExpiredSignatureError:
        # 만료된 token이라면 signin 페이지로 리디렉팅
        return redirect(url_for("signinpage", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        # 잘못된 token이라면 signin 페이지로 리디렉팅
        return redirect(url_for("signinpage", msg="로그인 정보가 존재하지 않습니다."))

# Todo 항목 삭제
@app.route("/todo/delete", methods=["POST"])
def deletetodo():  
    # token을 쿠키에서 불러오고,  
    token = request.cookies.get('token')
    try:
        # token을 디코드해서 유효한 토큰인지 확인
        _ = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        # POST로 받은 toDoId를 변수에 저장해서,
        todo_id = request.form["toDoId"]
        # 해당 toDoId를 todoList DB에서 삭제
        db.todoList.delete_one({'_id': ObjectId(todo_id)})
        # 결과 반환
        return jsonify({'result': 'success'})
    except jwt.ExpiredSignatureError:
        # 만료된 token이라면 signin 페이지로 리디렉팅
        return redirect(url_for("signinpage", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        # 잘못된 token이라면 signin 페이지로 리디렉팅
        return redirect(url_for("signinpage", msg="로그인 정보가 존재하지 않습니다."))

# 유저 리스트 반환
@app.route("/todo/share", methods=["GET"])
def shareIdList():
    # token을 쿠키에서 불러오고,
    token = request.cookies.get('token')
    try:
        # token을 디코드해서,
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        # id값으로 모든 todo를 찾아서 리스트로 만들고,
        all_list = list(db.user.find({}, {'_id': False, 'pw': False}))
        all_list = [i['id'] for i in all_list if i['id'] != payload['id']]
        print(all_list)
        # 반환
        return jsonify({'result': all_list})
    except jwt.ExpiredSignatureError:
        # 만료된 token이라면 signin 페이지로 리디렉팅
        return redirect(url_for("signinpage", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        # 잘못된 token이라면 signin 페이지로 리디렉팅
        return redirect(url_for("signinpage", msg="로그인 정보가 존재하지 않습니다."))
    
# Todo를 지정한 유저에게 공유
@app.route("/todo/share", methods=["POST"])
def sharing():
    # token을 쿠키에서 불러오고,
    token = request.cookies.get('token')
    # POST로 보내온 toDo 값을 변수에 저장하고,
    receiverId = request.form["receiverId"]
    toDo = request.form["toDo"]
    try:
        # token을 디코드해서,
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        # payload에 있는 아이디와 POST로 받은 toDo, status, sharedId를 DB에 저장
        # toDo 의 완료/미완료 상태 표시값인 status와 공유받은 아이디 값인 sharedId를 부여
        # status: False = 미완료, True = 완료
        status = False
        # shareId: None = 생성한 toDo, userId = 다른 유저로부터 공유받은 toDo
        sharedId = payload['id']
        doc = {'id': receiverId, 'toDo': toDo, 'status': status, 'sharedId': sharedId}
        db.todoList.insert_one(doc)
        # 저장한 결과를 반환
        return jsonify({'result': 'success'})
    except jwt.ExpiredSignatureError:
        # 만료된 token이라면 signin 페이지로 리디렉팅
        return redirect(url_for("signinpage", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        # 잘못된 token이라면 signin 페이지로 리디렉팅
        return redirect(url_for("signinpage", msg="로그인 정보가 존재하지 않습니다."))

if __name__ == '__main__':
    app.run('0.0.0.0', port=3000, debug=True)