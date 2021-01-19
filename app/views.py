import datetime
import json
from app import app
import os
import requests
from flask import render_template, redirect, request, session, g, url_for, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from app import db, User, mail
from datetime import timedelta
import time 
from flask_mail import Message


CONNECTED_NODE_ADDRESS= "http://127.0.0.1:8000"
#CONNECTED_NODE_ADDRESS= "http://0.0.0.0:8000"
admin_pasw="sha256$LEQYUVst$392ce5b09926d59d0107d0f2ae6d527a12f568f6c797ec72b2a1025fe004e3ad"

db.create_all()
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(minutes=15)
posts=[]


def fetch_posts():
    get_chain_address="{}/chain".format(CONNECTED_NODE_ADDRESS)
    response=requests.get(get_chain_address)
    if response.status_code== 200:
        content=[]
        chain =json.loads(response.content)
        for block in chain["chain"]:
            for tx in block["transactions"]:
                tx["index"]= block["index"]
                tx["hash"]= block ["previous_hash"]
                content.append(tx)

        global posts
        posts= sorted(content,
                      key=lambda k: k['timestamp'], reverse=True)

@app.route('/')
def index():
    fetch_posts()
    return render_template('search.html',
                           posts=None,
                           products=None,
                           node_address=CONNECTED_NODE_ADDRESS,
                           readable_time=timestamp_to_string)

@app.route('/mmi', methods=[ 'GET','POST'])
def mmi():
    if request.method == 'GET':
        return render_template("mmi.html",user=session['user'])
    if request.method == 'POST' and session['user']!="admin":
        p=None
        m=None
        s=None
        i=None
        try:
            p= request.form["password"] 
        except:
            try:
                m= request.form["mail"]
            except:
                try:
                    s= request.form["sede"] 
                except:
                    i= request.form["info"]  
        try:
            user = User.query.filter_by(p_iva=session['user']).first()       
            if p is not None:
                user.password=generate_password_hash(p, method='sha256')
                db.session.commit()

            if m is not None:
                user.email=m
                db.session.commit()

            if s is not None:
                user.sede=s
                db.session.commit()

            if i is not None:
                user.info=i
                db.session.commit()

            return render_template("mmi.html", ok = True,user=session['user'])
        except:
            return render_template("mmi.html", ok = False,user=session['user'])
    if request.method == 'POST' and session['user']=="admin":
        try:
            global admin_pasw
            admin_pasw=generate_password_hash(p, method='sha256')
            p= request.form["password"] 
            return render_template("mmi.html", ok = True,user=session['user'])

        except:
            return render_template("mmi.html", ok = False,user=session['user'])


@app.route('/protected')
def home_page():
    try:
    
        session['user']
        fetch_posts()
        return render_template('index.html',
                            posts=posts,
                            user=session['user'],
                            node_address=CONNECTED_NODE_ADDRESS,
                            readable_time=timestamp_to_string)
    except:
        return render_template('login.html')
                          
    
    

@app.route('/submit', methods= ['POST'])
def submit_texarea():
    fetch_posts()
    user = User.query.filter_by(p_iva=session['user']).first()
    info_author=user.info
    place_of_work=request.form["place_of_work"]
    tipe_of_author= request.form["type"]

    post_content= request.form["content"]
    nome_prod= request.form["nome_prod"]
    #bisogna riportare questo il nome dell'utente in sessione 
    author= user.name
    p_iva=user.p_iva
    cod_prod = request.form["cod_prod"]
    conc_prod= ''
    richiesta= True
    i=0
    c=0
    list_pr=list()
    while richiesta:
        try:
            i=i+1
            stringa =request.form["list_prod{}".format(i)]
            list_pr.append(stringa)
        except:
            break

    for i in list_pr:
        while richiesta:
            try:
                if posts[c]["cod_prod"]== i:
                    richiesta=False
                    c=0
                else:
                    c=c+1
            except:
                return render_template("index.html", message= "il codice "+i+"non esiste, prego riprova")



    if(len(list_pr)!=0):
        for i in list_pr:
            
            if i == list_pr[-1]:
                conc_prod = conc_prod +  i
            else:
                conc_prod = conc_prod +  i + ','

        post_object ={
            
            'author': author,
            'info_author': info_author,
            'p_iva':p_iva,
            'place_of_work': place_of_work,
            'tipe_of_author': tipe_of_author,
            'nome_prod': nome_prod,
            'content': post_content,
            'cod_prod': cod_prod,
            'list_prod': conc_prod

        }
    else:
          post_object ={
            
            'author': author,
            'info_author': info_author,
            'p_iva':p_iva,
            'place_of_work': place_of_work,
            'tipe_of_author': tipe_of_author,
            'nome_prod': nome_prod,
            'content': post_content,
            'cod_prod': cod_prod,
            'list_prod': ' '

        }

    new_tx_address="{}/new_transaction".format(CONNECTED_NODE_ADDRESS)
    requests.post(new_tx_address, json=post_object, headers={'Content-type': 'application/json'})
    
    return redirect(CONNECTED_NODE_ADDRESS+'/mine')

def timestamp_to_string(epoch_time):
    return datetime.datetime.fromtimestamp(epoch_time).strftime('%d-%m-%Y ')



    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session.permanent = True
        p_iva= request.form.get('p_iva')
        password = request.form.get('password')
        
        if (p_iva== "admin" and check_password_hash(admin_pasw,password) ):
            session['user'] = p_iva
            return redirect("/admin_user")

        user = User.query.filter_by(p_iva=p_iva).first()
        
    
        if not user or not check_password_hash(user.password, password): 
            flash('Please check your login details and try again.')
            return render_template('login.html')
        session['user'] = user.p_iva
  
        return redirect('/protected')
        
    return render_template('login.html')

@app.route('/admin_user', methods=['GET', 'POST'])
def admin_user():
    if request.method=='GET':
        
        cursore = db.engine.execute('SELECT p_iva, email, password,name, info, sede FROM user')
        return render_template ('admin_user.html', items = cursore.fetchall (),user=session['user'])
    
    if request.method=='POST':
        
        #cursore = db.engine.execute('SELECT p_iva, email, password,name, info, sede FROM user')
        try:
            pasw=request.form["password"]
            p_iva=request.form["p_iva"]
            user = User.query.filter_by(p_iva=p_iva).first()       
            user.password=generate_password_hash(pasw, method='sha256')
            db.session.commit()
        except:
            p_iva=request.form["p_iva"]
            user = User.query.filter_by(p_iva=p_iva).first()
            db.session.delete(user)
            db.session.commit()

        cursore = db.engine.execute('SELECT p_iva, email, password,name, info, sede FROM user')
        return render_template ('admin_user.html', items = cursore.fetchall (),user=session['user'])

    return render_template("admin_user.html", user=session['user'])

@app.route('/admin_chain', methods=['GET', 'POST'])
def admin_chain():
    try:
        out_file = open("Peers.txt","r")
        f = out_file.read()
        peers = f.split(",")
    except:
        peers = list()
    active_peers = list()

    for peer in peers:
        try:
            ccc = peer + ":8000/chain"
            c = requests.get("http://" + peer + ":8000/chain")
            active_peers.append(peer)
        except:
            continue


    global CONNECTED_NODE_ADDRESS
    if request.method=='GET':
        return render_template("admin_chain.html", user=session['user'], peers=active_peers, ip=CONNECTED_NODE_ADDRESS, len = len(active_peers))
    if request.method=='POST':
        try:    
            CONNECTED_NODE_ADDRESS= request.form['new_servernode']
            return render_template("admin_chain.html", user=session['user'], peers=active_peers, ok= True, ip=CONNECTED_NODE_ADDRESS)
        except:
            return render_template("admin_chain.html", user=session['user'], peers=active_peers, ok= False, ip=CONNECTED_NODE_ADDRESS)
    
    #tutti attivi




@app.route('/logout')
#@login_required
def logout():
    logout_user()
    session.pop('user', None)
    return redirect('/')





@app.route('/signup', methods=['GET','POST'])
def signup_post():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        p_iva=request.form.get('p_iva')
        info=request.form.get('info')
        sede=request.form.get('sede')

        if email=='':
            return render_template ('signup.html', message="Errore: email mancante")
        if name=='':
            return render_template ('signup.html', message="Errore: nome azienda mancante")
        if password=='':
            return render_template ('signup.html', message="Errore: password mancante")
        if p_iva=='':
            return render_template ('signup.html', message="Errore: partita iva mancante")
        if info=='':
            return render_template ('signup.html', message="Errore: informazioni mancanti")
        if sede=='':
            return render_template ('signup.html', message="Errore: sede mancante")

        if len(list(password))<8:
            return render_template ('signup.html', message="Errore: password non valida")

        user = User.query.filter_by(p_iva=p_iva).first() # 

        if user:
            return render_template('signup.html', message="Errore: partita iva già presente")

        new_user = User(p_iva=p_iva,email=email,  password=generate_password_hash(password, method='sha256'),name=name, info=info, sede=sede)

        db.session.add(new_user)
        db.session.commit()

        if request.form.get('check_blockchain') == 'on':

            return render_template('download.html')
        else:
            return render_template('login.html')

    else:
        return render_template('signup.html')

@app.route('/download', methods=['GET'])
def download():
    try:
        s = session['user']
        return render_template('download.html', user=session['user'])
    except:
        return render_template('download.html')

    
@app.route('/download_file')
def download_file():

	path = "../blockchain.zip"

	return send_file(path, as_attachment=True)


@app.route('/sync_node', methods=['POST'])
def sync():
    user = None
    try:
        user = session['user']
    except:
        pass
    ip = str(request.environ['REMOTE_ADDR'])
    s = "curl -X POST "+ip+":8000/register_with -H 'Content-Type: application/json' -d '{\"node_address\": \""+CONNECTED_NODE_ADDRESS+"\"}'"
    try:
        okk=False
        os.system(s)
        out_file = open("Peers.txt","r")
        f = out_file.read()
        out_file.close()
        ff = f.split(",")
        for i in ff:
            if i==ip:
                okk=True
                break
        if okk==False:
            out_file = open("Peers.txt","a")
            out_file.write(ip + ",")
            out_file.close()
        
        if (user != None):
            return render_template('download.html', ok=True, user = user)
        else:
            return render_template('download.html', ok=True)
    except:
        if (user != None):
            return render_template('download.html', ok=False , user = user)
        else:
            return render_template('download.html', ok=False)
        



    
    

@app.route('/search/<prodotto>',methods=['GET','POST'])
def search(prodotto='<None>'):
    if request.method=='GET' and prodotto=='<None>':
        try :
            session['user']
            return render_template('search.html',
                            user=session['user'],
                            posts=None,
                            products=None,
                            node_address=CONNECTED_NODE_ADDRESS,
                            readable_time=timestamp_to_string)  
        except:
            return render_template('search.html',
                            posts=None,
                            products=None,
                            node_address=CONNECTED_NODE_ADDRESS,
                            readable_time=timestamp_to_string)
    else:
        if request.method=='POST':
            cod= request.form['product']
        else:
            cod=prodotto
        get_chain_address="{}/chain".format(CONNECTED_NODE_ADDRESS)
        response=requests.get(get_chain_address)
        if response.status_code== 200:
            content=[]
            chain =json.loads(response.content)
            for block in chain["chain"]:
                for tx in block["transactions"]:
                    tx["index"]= block["index"]
                    tx["hash"]= block ["previous_hash"]
                    tx["timestamp"]= block ["timestamp"]
                    content.append(tx)
            total= sorted(content,
                        key=lambda k: k['timestamp'], reverse=True)
            correct_list=[]
            product_list=[]
            print()
            products={}
            for i in total:
                if(i['cod_prod'] == cod):
                    correct_list.append(i)
                    
                    
                    if i['list_prod']!=' ':
                        product_list.extend(i['list_prod'].split(','))
            
            for i in total:
                for p in product_list:
                    if i['cod_prod'] == p:
                        products[p]=i['nome_prod']
            try:
                session['user']!= None
                
                return render_template('search.html',
                    user=session['user'],
                    posts=correct_list,
                    products=products,
                    node_address=CONNECTED_NODE_ADDRESS,
                    readable_time=timestamp_to_string)
            except:
                 return render_template('search.html',

                            posts=correct_list,
                            products=products,
                            node_address=CONNECTED_NODE_ADDRESS,
                            readable_time=timestamp_to_string)  


@app.route('/error',methods=['GET'])
def error():
    return render_template('index.html',
                            posts=posts,
                            
                            user=session['user'],
                            node_address=CONNECTED_NODE_ADDRESS,
                            readable_time=timestamp_to_string,
                            error=True)

@app.route('/ok_trans',methods=['GET'])
def ok():
    return render_template('index.html',
                            posts=posts,
                            
                            user=session['user'],
                            node_address=CONNECTED_NODE_ADDRESS,
                            readable_time=timestamp_to_string,
                            ok=True)

@app.route('/ChiSiamo')
def ChiSiamo():
    try:
        s = session['user']
        return render_template('ChiSiamo.html', user=session['user'])
    except:
        return render_template('ChiSiamo.html')


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='marcociampa900@gmail,com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if request.method == "GET":
        return render_template('reset_password.html')
    elif request.method == "POST":
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            send_reset_email(user)
            flash('An email has been sent with instructions to reset your password.', 'info')
            return redirect('/login')
        else:
            flash("Questa email non corrisponde a nessun utente presente nel sistema! Controlla la tua mail!")
            return render_template('reset_password.html')


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    
    if request.method == "GET":
        
        user= User.verify_reset_token(token)
        if user is None:
            flash('That is an invalid or expired token', 'warning')
            return render_template('reset_password.html')
        else:
            return render_template('new_password.html')

    elif request.method =="POST":
        email = request.form.get('email')
        password = request.form.get('new_password')
        confirmed_password = request.form.get('confirmed_new_password')
        user = User.query.filter_by(email=email).first()
        if password == confirmed_password:
            
            hashed_password = generate_password_hash(password, method='sha256')

            user.password = hashed_password
            db.session.commit()
            flash('Your password has been updated! You are now able to log in', 'success')
            return render_template('login.html')
        else:
            flash('Password don\'t match!')
            return render_template('new_password.html')






        

