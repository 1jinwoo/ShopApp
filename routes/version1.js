// TODO : test all routes!! (Done: vendor/register, vendor/login)
// TODO: modify_product, display_cart, order_individual_item

require('dotenv/config');
const express = require('express');
const router = express.Router();
const pool = require('../db.js');
const squel = require('squel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const AWS = require('aws-sdk');
const multer = require('multer');
const multerS3 = require('multer-s3');

const BUCKET_NAME = process.env.AWS_S3_BUCKET_NAME || 'shopapp-img';
const IAM_USER_KEY = process.env.IAM_USER_KEY;
const IAM_USER_SECRET = process.env.IAM_USER_SECRET;

const dbErrorMessage = "데이터베이스 상의 문제로 작업이 취소되었습니다."
const serverErrorMessage = "서버 문제로 에러가 발생하였습니다. 빠른 시일내로 조치하도록 하겠습니다."
const loginErrorMessage = "로그인 과정에서 문제가 발생하였습니다. 다시 시도해주시기 바랍니다."

const s3bucket = new AWS.S3({
    accessKeyId: IAM_USER_KEY,
    secretAccessKey: IAM_USER_SECRET,
    Bucket: BUCKET_NAME
});

const upload = multer({
    storage: multerS3({
        s3: s3bucket,
        bucket: 'shopapp-img',
        acl: 'public-read-write',
        contentType: function(req, file, cb){
            cb(null, file.mimetype);    
        },
        metadata: function (req, file, cb) {
            cb(null, {fieldName: file.fieldname, 'Content-Type': file.mimetype, 'Cache_control': 'public, max-age=31536000'});
        },
        key: function (req, file, cb) {
            var date = getDateSerial();
            if (req.customer_id == undefined && req.vendor_id){
                cb(null, `v1/vendor${req.vendor_id}/products` + "/product" + 
                   req.body.product_id+  "_" +  date + "_" + req.files.length) 
            } else if (req.vendor_id == undefined && req.customer_id){
                cb(null, file.fieldname + "/"+ req.username + "_" +  date) 
            } else{
                cb(null, "v1/products" + "/product" +  date) 
            }
        }
    })
});

// Customer: verify user upon login request using hash function, provides token if success
router.post('/api/login', function(req, res, next){
    if (!req.body.username){
        res.status(401).json({
            error_message: "REQUIRED FIELDS: (username, password)",
            display_message: "아이디를 입력해 주세요."
        });
    } else if (!req.body.password){
        res.status(401).json({
            error_message: "REQUIRED FIELDS: (username, password)",
            display_message: "비밀번호를 입력해 주세요"
        });
    } else {

        pool.getConnection(function(error,connection){

            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }

                error.type = "pool.getConnection";
                error.identity = null;
                error.time = getDateString();
                error.status = 500;
                error.display_message = dbErrorMessage;
                next(error);
            } 

            else{
                var loginUser = req.body;
                var queryString = squel.select({separator:"\n"})
                                    .field('password')
                                    .field('customer_id', 'id')
                                    .field('customer_fullname', 'customer_name')
                                    .field('vendor_id')
                                    .from('customers')
                                    .where('username =?',loginUser.username )
                                    .where('vendor_id = ?', loginUser.vendor_id)
                                    .toString();
                
                // SELECT query: fetch customer data
                connection.query(queryString, function(error, results, fields){
                    connection.release();

                    if(error){
                        error.type = "connection.query";
                        error.identity = null;
                        error.time = getDateString();
                        error.status = 500;
                        error.query_index = 1;
                        error.display_message = serverErrorMessage;
                        next(error);
                    } 
                    
                    else{
                        // if customer exists
                        if (!!results[0]){
                            var isValid = bcrypt.compareSync(loginUser.password, results[0].password);
                            
                            // if password is valid
                            if (isValid){
                                jwt.sign({username: loginUser.username, customer_id: results[0].id,
                                full_name: results[0].customer_name, vendor_id: results[0].vendor_id},
                                process.env.USER_SECRET_KEY, {expiresIn: '7d'}, 
                                function(error, token){

                                    if (error){
                                        error.type = "jwt.sign";
                                        error.identity = null;
                                        error.time = getDateString();
                                        error.status = 500;
                                        error.display_message = loginErrorMessage;
                                        next(error);
                                    } 

                                    else{
                                        res.status(200).json({
                                            auth: true,
                                            token: token
                                        });
                                    }
                                });
                            } 
                            
                            // if invalid password
                            else {
                                res.status(401).json({
                                    display_message: "비밀번호가 일치하지 않습니다",
                                    auth: false,
                                    token: null
                                });
                            }
                        } 
                        
                        // if no such customer exists
                        else{
                            res.status(401).json({
                                display_message: "해당 아이디가 존재하지 않습니다",
                                auth: false,
                                token: null
                            });
                        }
                    }
                });
            }
        });
    }
});

// Customer: register new customer data using hash function
router.post('/api/register', function(req, res, next){
    if (!req.body.vendor_id || !req.body.username || !req.body.password || !req.body.first_name
        || !req.body.password_confirm || !req.body.last_name || !req.body.phone || !req.body.gender
        || !req.body.address1 || !req.body.city || !req.body.postal_code){
        res.status(401).json({
            error_message: "REQUIRED FIELDS(vendor_id, username, password, first_name, last_name"
                + ", phone, address1, city, postal_code)",
            display_message: "필수 항목을 모두 입력해 주세요"
        });
    } else if (req.body.username.length < 5 || req.body.username.length > 20){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 소비자 아이디(username)",
            display_message: "아이디가 5자 이상, 20자 이하이어야 합니다"
        });
    } else if (req.body.password.length < 6 || req.body.password.length > 16){
        res.status(401).json({
            error_messsage: "유효하지 않은 데이터: 소비자 비밀번호(password)",
            display_message: "비밀번호가 6자 이상, 16자 이하이어야 합니다"
        });
    } else if (req.body.password != req.body.password_confirm){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 소비자 비밀번호 확인(password_confirm)",
            display_message: "비밀번호와 비밀번호 확인이 일치하지 않습니다"
        });
    } else if (req.body.gender != 'male' && req.body.gender != 'female') {
        res.status(401).json({
            display_message: "알 수 없는 오류가 발생하였습니다"
        });
    } else if (req.body.address1.length > 25){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 소비자 주소1(address1)",
            display_message: "주소1이 25자 이하여야 합니다."
        });
    } else if (req.body.city.length > 20){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 소비자 도시(city)",
            display_message: "도시가 20자 이하여야 합니다."
        });
    } else if (req.body.phone.length > 15){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 소비자 전화번호(phone)",
            display_message: "전화번호가 15자 이하여야 합니다."
        });
    } else if (req.body.postal_code.length > 10){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 소비자 우편번호(postal_code)",
            display_message: "우편번호가 20자 이하여야 합니다."
        });
    } else{

        pool.getConnection(function(error,connection){

            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }

                error.type = "pool.getConnection";
                error.identity = null;
                error.time = getDateString();
                error.status = 500;
                error.display_message = dbErrorMessage;
                next(error);
            } 

            else{
                var newCustomer = req.body;
                bcrypt.hash(newCustomer.password, 10, function(error, hash) {

                    if(error) {
                        connection.release();
                        error.type = "bcrypt.hash";
                        error.identity = null;
                        error.time = getDateString();
                        error.status = 500;
                        error.display_message = loginErrorMessage;
                        next(error);
                    } 

                    else {
                        var pwHash = hash;
                        var registerQuery = squel.insert({separator:"\n"})
                                    .into('customers')
                                    .set('vendor_id', newCustomer.vendor_id)
                                    .set('username', newCustomer.username)
                                    .set('password', pwHash)
                                    .set('customer_lastname', newCustomer.last_name)
                                    .set('customer_firstname', newCustomer.first_name)
                                    .set('customer_fullname', newCustomer.last_name+newCustomer.first_name)
                                    .set('customer_gender', newCustomer.gender)
                                    .set('customer_phone', newCustomer.phone)
                                    .set('customer_address_line1', newCustomer.address1)
                                    .set('customer_address_line2', newCustomer.address2)
                                    .set('customer_city', newCustomer.city)
                                    .set('customer_postal_code', newCustomer.postal_code)
                                    .set('customer_country', newCustomer.country)
                                    .set('customer_email', newCustomer.email)
                                    .toString();

                        // INSERT query: insert new customer data
                        connection.query(registerQuery, function(error, results, fields){

                            if(error){
                                connection.release();
                                error.type = "connection.query";
                                error.identity = null;
                                error.time = getDateString();
                                error.status = 500;
                                error.query_index = 1;
                                error.display_message = serverErrorMessage;
                                next(error);
                            }
                            
                            else{
                                var requestQuery = squel.select({separator:"\n"})
                                                        .field('username')
                                                        .field('customer_fullname', 'customer_name')
                                                        .field('vendor_id')
                                                        .from('customers')
                                                        .where('customer_id =?', results.insertId)
                                                        .toString();
                                
                                // SELECT query: check if new customer data was properly inserted
                                connection.query(requestQuery, function(error, results2, fields2){
                                    connection.release();

                                    if (error){
                                        error.type = "connection.query";
                                        error.identity = null;
                                        error.time = getDateString();
                                        error.status = 500;
                                        error.query_index = 2;
                                        error.display_message = dbErrorMessage;
                                        next(error);
                                    } 
                                    
                                    else{
                                        // if properly inserted
                                        if (!!results2) {
                                            jwt.sign({username: results2[0].username, customer_id: results.insertId,
                                            full_name: results2[0].customer_name, vendor_id: results2[0].vendor_id},
                                            process.env.USER_SECRET_KEY, {expiresIn: '7d'}, 
                                            function(error, token){

                                                if (error){
                                                    error.type = "jwt.sign";
                                                    error.identity = null;
                                                    error.time = getDateString();
                                                    error.status = 500;
                                                    error.display_message = loginErrorMessage;
                                                    next(error);
                                                } 

                                                else{
                                                    res.status(200).json({
                                                        message: "회원가입이 완료되었습니다",
                                                        auth: true,
                                                        token: token
                                                    });
                                                }
                                            });
                                        } 

                                        // if not inserted
                                        else{
                                            res.status(500).json({
                                                error_message: "데이터 베이스에 정보가 등록되지 않았습니다",
                                                display_message: "알 수 없는 오류"
                                            });
                                        }
                                    }
                                })
                            }
                        });
                    }
                });
            }
        });
    }
});

// Customer: change password once login-ed
router.put('/api/register', verifyToken, function(req, res, next){
    if (!req.body.password || !req.body.new_password || !req.body.new_password_confirm){
        res.status(401).json({
            error_message: "REQUIRED FIELDS (password, new_password, new_password_confirm",
            display_message: "필수 항목을 모두 입력해 주세요"
        });
    } else if (req.body.password == req.body.new_password){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 소비자 새 비밀번호 (new_password)",
            display_message: "새 비밀번호를 현재 비밀번호와 다르게 설정하세요"
        });
    } else if (req.body.new_pasword != req.body.new_password_confirm){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 소비자 새 비밀번호 확인 (new_password_confirm)",
            display_message: "새 비밀번호가 일치하지 않습니다"
        });
    } else if (req.body.new_password.length < 6 || req.body.new_password.length > 16){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 소비자 새 비밀번호 (new_password)",
            display_message: "새 비밀번호를 6자 이상, 16자 이하로 설정해 주세요"
        });
    } else{

        pool.getConnection(function(error,connection){

            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }
                error.type = "pool.getConnection";
                error.identity = '[CUSTOMER]' + req.customer_id;
                error.time = getDateString();
                error.status = 500;
                error.display_message = dbErrorMessage;
                next(error);
            } 
            
            else{
                var queryString = squel.select({separator:"\n"})
                                    .from('customers')
                                    .field('password')
                                    .where('username = ?', req.username)
                                    .where('vendor_id = ?', req.vendor_id)
                                    .toString();

                // SELECT query: fetch customer's hashed password
                connection.query(queryString, function(error, results, fields){

                    if (error){
                        connection.release();
                        error.type = "connection.query";
                        error.identity = '[CUSTOMER]' + req.customer_id;
                        error.time = getDateString();
                        error.status = 500;
                        error.query_index = 1;
                        error.display_message = serverErrorMessage;
                        next(error);
                    } 
                    
                    else{
                        var isValid = bcrypt.compareSync(req.body.password, results[0].password);

                        // if password is invalid
                        if (!isValid) {
                            connection.release();
                            res.status(401).json({
                                message: '입력하신 비밀번호가 일치하지 않습니다'
                            });
                        }
                        // if the password is valid
                        else {
                            var newPwHashed = bcrypt.hashSync(req.body.new_password, 10);
                            var changeQuery = squel.update({separator:"\n"})
                                                .table('customers')
                                                .set('password', newPwHashed)
                                                .where('username = ?', req.username)
                                                .where('vendor_id = ?', req.vendor_id)
                                                .toString();

                            // UPDATE query: change hashed password for the customer
                            connection.query(changeQuery, function(error, results2, fields2){
                                connection.release();
                                
                                if (error){
                                    error.type = "connection.query";
                                    error.identity = '[CUSTOMER]' + req.customer_id;
                                    error.time = getDateString();
                                    error.status = 500;
                                    error.query_index = 2;
                                    error.display_message = serverErrorMessage;
                                    next(error);
                                } 
                                else{
                                    res.status(200).json({
                                        message: "비밀번호가 성공적으로 변경되었습니다"
                                    });
                                }
                            });
                        }
                    }
                });
            }
        });
    }
});
 
// Customer: add product to the customer's shopping cart
router.post('/api/add_to_cart', verifyToken, function(req, res, next){
    pool.getConnection(function(error,connection){

        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }

            error.type = "pool.getConnection";
            error.identity = '[CUSTOMER]' + req.customer_id;
            error.time = getDateString();
            error.status = 500;
            error.display_message = dbErrorMessage;
            next(error);
        } 
        
        else{
            var checkString = squel.select({separator:"\n"})
                                   .from('carts')
                                   .field('cart_id')
                                   .where('customer_id =?', req.customer_id)
                                   .toString();

            // SELECT query: check if the customer's cart exists
            connection.query(checkString, function(error, results, fields){

                if (error){
                    connection.release();
                    error.type = "connection.query";
                    error.identity = '[CUSTOMER]' + req.customer_id;
                    error.time = getDateString();
                    error.status = 500;
                    error.query_index = 1;
                    error.display_message = serverErrorMessage;
                    next(error);
                } 
                
                else{
                    // if cart doesn't exist
                    if(!results.length){

                        connection.beginTransaction(function(error){
                            if (error){
                                connection.release();
                                error.type = "connection.beginTransaction";
                                error.identity = '[CUSTOMER]' + req.customer_id;
                                error.time = getDateString();
                                error.status = 500;
                                error.display_message = dbErrorMessage;
                                next(error);
                            }

                            var insertCartString = squel.insert({separator:"\n"})
                                                        .into('carts')
                                                        .set('customer_id', req.customer_id)
                                                        .toString();

                            // INSERT query: make new cart
                            connection.query(insertCartString, function(error, results2, fields2){
                                if (error){
                                    return connection.rollback(function(){
                                        connection.release();
                                        error.type = "connection.query";
                                        error.identity = '[CUSTOMER]' + req.customer_id;
                                        error.time = getDateString();
                                        error.status = 500;
                                        error.index_in_transaction = 1;
                                        error.display_message = dbErrorMessage;
                                        next(error);
                                    });
                                }

                                var insertPCString = squel.insert({separator:"\n"})
                                                          .into('products_carts')
                                                          .set('cart_id', results2.insertId)
                                                          .set('product_id', req.body.product_id)
                                                          .set('cart_quantity', req.body.quantity)
                                                          .toString();

                                // INSERT query: insert new rows to products_carts for products
                                connection.query(insertPCString, function(error, results3, fields3){
                                    if (error){
                                        return connection.rollback(function(){
                                            connection.release();
                                            error.type = "connection.query";
                                            error.identity = '[CUSTOMER]' + req.customer_id;
                                            error.time = getDateString();
                                            error.status = 500;
                                            error.index_in_transaction = 2;
                                            error.display_message = dbErrorMessage;
                                            next(error);
                                        });
                                    }

                                    connection.commit(function(error){
                                        if (error){
                                            return connection.rollback(function(){
                                                connection.release();
                                                error.type = "connection.commit";
                                                error.identity = '[CUSTOMER]' + req.customer_id;
                                                error.time = getDateString();
                                                error.status = 500;
                                                error.display_message = dbErrorMessage;
                                                next(error);
                                            });
                                        }

                                        connection.release();
                                        res.status(200).json({
                                            message: "상품이 장바구니에 추가되었습니다"
                                        });
                                    });
                                });
                            });
                        });
                    } 
                    
                    // If cart does exist
                    else{
                        var checkString2 = squel.select({separator:"\n"})
                                                .from('products_carts')
                                                .field('cart_quantity')
                                                .where('cart_id =?', results[0].cart_id)
                                                .where('product_id =?', req.body.product_id)
                                                .toString();

                        // SELECT query: check if the product is already in the cart
                        connection.query(checkString2, function(error, results2, fields2){

                            if (error){
                                connection.release();
                                error.type = "connection.query";
                                error.identity = '[CUSTOMER]' + req.customer_id;
                                error.time = getDateString();
                                error.status = 500;
                                error.query_index = 2;
                                error.display_message = serverErrorMessage;
                                next(error);
                            } 
                            
                            else{
                                var addCartString;
                                
                                // if product exists in cart
                                if (results2.length){
                                    addCartString = squel.update({separator:"\n"})
                                                        .table('products_carts')
                                                        .set(`cart_quantity = cart_quantity + ${req.body.quantity}`)
                                                        .where('cart_id =?', results[0].cart_id)
                                                        .where('product_id =?', req.body.product_id)
                                                        .toString();
                                } 

                                // if not
                                else{
                                    addCartString = squel.insert({separator:"\n"})
                                                        .into('products_carts')
                                                        .set('cart_id', results[0].cart_id)
                                                        .set('product_id', req.body.product_id)
                                                        .set('cart_quantity', req.body.quantity)
                                                        .toString();
                                }
                                
                                // INSERT query: add products to existing cart
                                connection.query(addCartString, function(error, results3, fields3){
                                    connection.release();

                                    if (error){
                                        error.type = "connection.query";
                                        error.identity = '[CUSTOMER]' + req.customer_id;
                                        error.time = getDateString();
                                        error.status = 500;
                                        error.query_index = 3;
                                        error.display_message = serverErrorMessage;
                                        next(error);
                                    } 
                                    else{
                                        res.status(200).json({
                                            message: "상품이 장바구니에 추가되었습니다"
                                        });
                                    }
                                });
                            } 
                        });
                    }
                }
            });
        }
    });
});

// Customer: modify customer's shopping cart with given cart_id
router.post('/api/modify_cart/:cart_id', verifyToken, function(req, res, next){
    pool.getConnection(function(error,connection){

        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            error.type = "pool.getConnection";
            error.identity = '[CUSTOMER]' + req.customer_id;
            error.time = getDateString();
            error.status = 500;
            error.display_message = dbErrorMessage;
            next(error);
        }
        else {
            var modifyString;

            // if delete a product from cart
            if (req.body.quantity == 0){
                modifyString = squel.delete({separator:"\n"})
                                    .from('products_carts')
                                    .where('product_id =?', req.body.product_id)
                                    .where('cart_id =?', req.params.cart_id)
                                    .toString();
            } 
            // if decrease quantity
            else{
                modifyString = squel.update({separator:"\n"})
                                    .table('products_carts')
                                    .set('cart_quantity', req.body.quantity)
                                    .where('product_id =?', req.body.product_id)
                                    .where('cart_id =?', req.params.cart_id)
                                    .toString();
            }

            // DELETE or UPDATE: modify a product's quantity in cart
            connection.query(modifyString, function(error, results, fields){
                connection.release();

                if (error){
                    error.type = "connection.query";
                    error.identity = '[CUSTOMER]' + req.customer_id;
                    error.time = getDateString();
                    error.status = 500;
                    error.query_index = 1;
                    error.display_message = serverErrorMessage;
                    next(error);
                } 
                else{
                    res.status(200).json({
                        message: "성공적으로 장바구니가 변경되었습니다"
                    });
                }
            });
        }
    });
})

// Customer: order products from the shopping cart
router.post('/api/order_products', verifyToken, function(req, res, next){
    pool.getConnection(function(error,connection){

        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }

            error.type = "pool.getConnection";
            error.identity = '[CUSTOMER]' + req.customer_id;
            error.time = getDateString();
            error.status = 500;
            error.display_message = dbErrorMessage;
            next(error);
        } 
        else{
            var productsQuery = squel.select({separator:"\n"})
                                     .field('pc.product_id')
                                     .field('pc.cart_quantity')
                                     .from('carts', 'c')
                                     .join('products_carts', 'pc', 'pc.cart_id = c.cart_id')
                                     .where('c.cart_id =?', req.body.cart_id)
            var checkString = squel.select({separator:"\n"})
                                   .field('p.product_id')
                                   .field('p.stock_quantity')
                                   .field('p.price_original')
                                   .field('p.price_discounted')
                                   .field('c.cart_quantity')
                                   .from('products', 'p')
                                   .join(productsQuery, 'c', 'c.product_id = p.product_id')
                                   .toString();
            
            // SELECT query: select data of products in the cart
            connection.query(checkString, function(error, results, fields){
                if (error){
                    connection.release();
                    error.type = "connection.query";
                    error.identity = '[CUSTOMER]' + req.customer_id;
                    error.time = getDateString();
                    error.status = 500;
                    error.query_index = 1;
                    error.display_message = serverErrorMessage;
                    next(error);
                } 

                else{
                    var isNotEnough = 0;
                    for (i = 0; i < results.length; i++) {
                        if (results[i].stock_quantity < results[i].cart_quantity) {
                            isNotEnough = 1;
                        }
                    }

                    // if there aren't enough stock
                    if (isNotEnough){
                        connection.release();
                        res.status(401).json({
                            message: "상품의 재고가 충분하지 않습니다"
                        });
                    } 
                    
                    else{
                        connection.beginTransaction(function(error){
                            if(error){
                                connection.release();
                                error.type = "connection.beginTransaction";
                                error.identity = '[CUSTOMER]' + req.customer_id;
                                error.time = getDateString();
                                error.status = 500;
                                error.display_message = dbErrorMessage;
                                next(error);
                            }

                            var clauseString = 'UPDATE products SET stock_quantity = CASE product_id ';
                            var whereString = 'WHERE product_id IN (';
                            var newQuantity;

                            // Generate UPDATE query string to update multiple products at once
                            for (i = 0; i < results.length; i++) {
                                newQuantity = results[i].stock_quantity - results[i].cart_quantity;
                                clauseString += `WHEN ${results[i].product_id} THEN ${newQuantity} `;
                                whereString += `${results[i].product_id}`;
                                if (i != (results.length - 1)) {
                                    whereString += ', ';
                                } else{
                                    clauseString += 'END ';
                                    whereString += ')';
                                }
                            }

                            var updateString = clauseString + whereString;
                            
                            // UPDATE query: update products table (stock quantity) 
                            connection.query(updateString, function(error, results2, fields2){
                                if (error){
                                    return connection.rollback(function(){
                                        connection.release();
                                        error.type = "connection.query";
                                        error.identity = '[CUSTOMER]' + req.customer_id;
                                        error.time = getDateString();
                                        error.status = 500;
                                        error.index_in_transaction = 1;
                                        error.display_message = dbErrorMessage;
                                        next(error);
                                    });
                                }

                                var totalPrice = 0;
                                var insertArray = [];

                                // Generate object which will be used for INSERT query, and total price
                                for (i = 0; i < results.length; i++){
                                    if (results[i].price_discounted){
                                        totalPrice += (results[i].price_discounted * results[i].cart_quantity);
                                        insertArray.push({
                                            product_id: results[i].product_id,
                                            price_each: results[i].price_discounted,
                                            order_quantity: results[i].cart_quantity
                                        });
                                    } else{
                                        totalPrice += (results[i].price_original * results[i].cart_quantity);
                                        insertArray.push({
                                            product_id: results[i].product_id,
                                            price_each: results[i].price_original,
                                            order_quantity: results[i].cart_quantity
                                        });
                                    }
                                }

                                var insertString = squel.insert({separator:"\n"})
                                                        .into('orders')
                                                        .set('customer_id', req.customer_id)
                                                        .set('vendor_id', req.vendor_id)
                                                        .set('price_total', totalPrice)
                                                        .set('order_date', 'NOW()')
                                                        .set('order_status', 'ordered')
                                                        .set('order_address_line1', req.body.address1)
                                                        .set('order_address_line2', req.body.address2)
                                                        .set('order_city', req.body.city)
                                                        .set('order_country', req.body.country)
                                                        .set('order_postal_code', req.body.postal_code)
                                                        .set('order_name', req.body.name)
                                                        .set('order_phone', req.body.phone)
                                                        .set('order_email', req.body.email)
                                                        .toString();

                                // INSERT query: insert new order data into orders table
                                connection.query(insertString, function(error, results3, fields3){
                                    if (error){
                                        return connection.rollback(function(){
                                            connection.release();
                                            error.type = "connection.query";
                                            error.identity = '[CUSTOMER]' + req.customer_id;
                                            error.time = getDateString();
                                            error.status = 500;
                                            error.index_in_transaction = 2;
                                            error.display_message = dbErrorMessage;
                                            next(error);
                                        });
                                    }
                                    for (i = 0; i < results.length; i++){
                                        insertArray[i].order_id = results3.insertId;
                                    }

                                    var insertString2 = squel.insert({separator:"\n"})
                                                             .into('orderdetails')
                                                             .setFieldsRows(insertArray)
                                                             .toString();

                                    // INSERT query: insert individual product's order details
                                    connection.query(insertString2, function(error, results4, fields4){
                                        if (error){
                                            return connection.rollback(function(){
                                                connection.release();
                                                error.type = "connection.query";
                                                error.identity = '[CUSTOMER]' + req.customer_id;
                                                error.time = getDateString();
                                                error.status = 500;
                                                error.index_in_transaction = 3;
                                                error.display_message = dbErrorMessage;
                                                next(error);
                                            });
                                        }

                                        var paymentString = squel.insert({separator:"\n"})
                                                                 .into('payments')
                                                                 .set('order_id', results3.insertId)
                                                                 .set('amount', totalPrice)
                                                                 //.set('payment_method', ?)
                                                                 .toString();

                                        // INSERT : insert payment data
                                        connection.query(paymentString, function(error, results5, fields5){
                                            if (error){
                                                return connection.rollback(function(){
                                                    connection.release();
                                                    error.type = "connection.query";
                                                    error.identity = '[CUSTOMER]' + req.customer_id;
                                                    error.time = getDateString();
                                                    error.status = 500;
                                                    error.index_in_transaction = 4;
                                                    error.display_message = dbErrorMessage;
                                                    next(error);
                                                });
                                            }
                                            
                                            var deleteString = squel.delete({separator:"\n"})
                                                                   .from('carts')
                                                                   .where('cart_id =?', req.body.cart_id)
                                                                   .toString();

                                            // DELETE: delete cart
                                            connection.query(deleteString, function(error, results6, fields6){
                                                if (error){
                                                    return connection.rollback(function(){
                                                        connection.release();
                                                        error.type = "connection.query";
                                                        error.identity = '[CUSTOMER]' + req.customer_id;
                                                        error.time = getDateString();
                                                        error.status = 500;
                                                        error.index_in_transaction = 5;
                                                        error.display_message = dbErrorMessage;
                                                        next(error);
                                                    });
                                                }

                                                connection.commit(function(error){
                                                    if (error){
                                                        return connection.rollback(function(){
                                                            connection.release();
                                                            error.type = "connection.commit";
                                                            error.identity = '[CUSTOMER]' + req.customer_id;
                                                            error.time = getDateString();
                                                            error.status = 500;
                                                            error.display_message = dbErrorMessage;
                                                            next(error);
                                                        });
                                                    }

                                                    connection.release();
                                                    res.status(200).json({
                                                        message: "주문이 성공적으로 완료되었습니다",
                                                    });
                                                });
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    }
                }
            });
        }
    });
});

// Customer: list all products in the given category_id
router.get('/api/list_products/category/:category_id', function(req, res, next){
    pool.getConnection(function(error, connection){

        if (error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }

            error.type = "pool.getConnection";
            error.identity = null;
            error.time = getDateString();
            error.status = 500;
            error.display_message = dbErrorMessage;
            next(error);
        }

        else {
            var requestString = squel.select({separator:"\n"})
                                      .from('categories')
                                      .field('lft')
                                      .field('rgt')
                                      .field('category_name')
                                      .where('category_id = ?', req.params.category_id)
                                      .toString();

            // SELECT: acquire lft and rgt value of the given category
            connection.query(requestString, function(error, results, fields){
                if (error){
                    connection.release();
                    error.type = "connection.query";
                    error.identity = null;
                    error.time = getDateString();
                    error.status = 500;
                    error.query_index = 1;
                    error.display_message = serverErrorMessage;
                } 
                
                else{
                    var categoriesQuery = squel.select({separator:"\n"})
                                                .from('categories')
                                                .where('lft >= ?', results[0].lft)
                                                .where('rgt <= ?', results[0].rgt)
                    var productsString = squel.select({separator:"\n"})
                                              .from('products', 'p')
                                              .join(categoriesQuery, 'c', 'p.category_id = c.category_id')
                                              .field('p.product_name')
                                              .field('p.price_original')
                                              .field('p.price_discounted')
                                              .field('p.tag')
                                              .field('p.product_description')
                                              .field('p.product_rating')
                                              .toString();
                        
                    // SELECT: select all products within the given category
                    connection.query(productsString, function(error, products, fields2){
                        connection.release();

                        if (error){
                            error.type = "connection.query";
                            error.identity = null;
                            error.time = getDateString();
                            error.status = 500;
                            error.query_index = 2;
                            error.display_message = serverErrorMessage;
                        }

                        else{
                            res.status(200).json({
                                category: results[0].category_name,
                                products
                            });
                        }
                    });
                    
                }
            });
        }
    });
});

// Customer: get product information of an individual item
router.get('/api/products/:product_id', function(req, res, next){
    pool.getConnection(function(error, connection){

        if (error){
            if (typeof connection !== 'undefined'){
                connection.release();
            }
            
            error.type = "pool.getConnection";
            error.identity = null;
            error.time = getDateString();
            error.status = 500;
            error.display_message = dbErrorMessage;
            next(error);
        }

        else{
            var productString = squel.select({separator:"\n"})
                                     .from('products')
                                     .field('product_name')
                                     .field('stock_quantity')
                                     .field('price_original')
                                     .field('price_discounted')
                                     .field('tag')
                                     .field('product_description')
                                     .field('product_rating')
                                     .where('product_id = ?', req.params.product_id)
                                     .toString();
            
            // SELECT: fetch product data
            connection.query(productString, function(error, products, fields){
                if (error){
                    connection.release();
                    error.type = "connection.query";
                    error.identity = null;
                    error.time = getDateString();
                    error.status = 500;
                    error.query_index = 1;
                    error.display_message = serverErrorMessage;
                    next(error);
                }

                else {
                    var reviewString = squel.select({separator:"\n"})
                                            .from('reviews')
                                            .field('customer_id')
                                            .field('review_date')
                                            .field('review_rating')
                                            .field('review_text')
                                            .toString();

                    connection.query(reviewString, function(error, reviews, fields2){
                        connection.release();

                        if (error){
                            error.type = "connection.query";
                            error.identity = null;
                            error.time = getDateString();
                            error.status = 500;
                            error.query_index = 2;
                            error.display_message = serverErrorMessage;
                            next(error);
                        }

                        else {
                            var productInformation = products[0]

                            // if there are enough stock quantity
                            if (productInformation.stock_quantity > 0){
                                productInformation.stock_quantity = "재고 있음";
                            } else { // if not
                                productInformation.stock_quantity = "재고 없음";
                            }

                            res.status(200).json({
                                productInformation,
                                reviews
                            });
                        }
                    });
                }
            });
        }
    });
});

// Customer: post review on a product
// Only availabe when 
// 1. the customer has purchased the product and
// 2. the customer has not reviewed the product already
router.post('/api/post_review/product/:product_id', verifyToken, function(req, res, next){
    if (req.body.rating == undefined){
        res.status(401).json({
            error_message: "REQUIRED FIELDS : (rating)",
            display_message: "평점을 선택해 주세요"
        });
    } else if (req.body.rating < 0 || req.body.rating > 5){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 평점 (rating)",
            display_message: "평점은 1점에서 5점 사이어야 합니다"
        });
    } else{

        pool.getConnection(function(error, connection){

            if (error){
                if (typeof error !== 'undefined'){
                    connection.release();
                }

                error.type = "pool.getConnection";
                error.identity = '[CUSTOMER]' + req.customer_id;
                error.time = getDateString();
                error.status = 500;
                error.display_message = dbErrorMessage;
                next(error);
            } 
            else{
                var customerOrders = squel.select({separator:"\n"})
                                        .from('orders')
                                        .field('order_id')
                                        .where('customer_id = ?', req.customer_id)
                var checkOrderString = squel.select({separator:"\n"})
                                            .from(customerOrders, 'co')
                                            .join('orderdetails', 'od', 'co.order_id = od.order_id')
                                            .field('od.product_id')
                                            .where('od.product_id = ?', req.params.product_id)
                                            .toString();

                // SELECT: check if the customer has purchased the product
                connection.query(checkOrderString, function(error, results, fields){
                    if (error){
                        connection.release();
                        error.type = "connection.query";
                        error.identity = '[CUSTOMER]' + req.customer_id;
                        error.time = getDateString();
                        error.status = 500;
                        error.query_index = 1;
                        error.display_message = serverErrorMessage;
                        next(error);
                    } 
                    
                    else{
                        // if not purchased
                        if (!results.length){
                            connection.release();
                            res.status(401).json({
                                message: "구입하신 상품에 한해서만 리뷰 작성이 가능합니다"
                            });
                        } 

                        // if purchased
                        else{
                            var checkReviewString = squel.select({separator:"\n"})
                                                        .from('reviews')
                                                        .field('review_id')
                                                        .where('customer_id = ?', req.customer_id)
                                                        .where('product_id = ?', req.params.product_id)
                                                        .toString();

                            // SELECT: check if the customer already has reviewed the product
                            connection.query(checkReviewString, function(error, results2, fields){
                                if (error){
                                    connection.release();
                                    error.type = "connection.query";
                                    error.identity = '[CUSTOMER]' + req.customer_id;
                                    error.time = getDateString();
                                    error.status = 500;
                                    error.query_index = 2;
                                    error.display_message = serverErrorMessage;
                                    next(error);
                                }

                                else{
                                    // if reviewed
                                    if (results2.length){
                                        res.status(401).json({
                                            message: "이미 리뷰가 완료된 상품입니다"
                                        });
                                    } 
                                    // if not
                                    else{
                                        connection.beginTransaction(function(error){
                                            if (error){
                                                connection.release();
                                                error.type = "connection.beginTransaction";
                                                error.identity = '[CUSTOMER]' + req.customer_id;
                                                error.time = getDateString();
                                                error.status = 500;
                                                error.display_message = dbErrorMessage;
                                                next(error);
                                            }

                                            var insertReviewString = squel.insert({separator:"\n"})
                                                                        .into('reviews')
                                                                        .set('customer_id', req.customer_id)
                                                                        .set('product_id', req.params.product_id)
                                                                        .set('review_date', 'NOW()')
                                                                        .set('review_rating', req.body.rating)
                                                                        .set('review_text', req.body.review_text)
                                                                        .toString();
                                                                    
                                            // INSERT: insert new review into review table
                                            connection.query(insertReviewString, function(error, results3,fields3){
                                                if (error){
                                                    return connection.rollback(function(){
                                                        connection.release();
                                                        error.type = "connection.query";
                                                        error.identity = '[CUSTOMER]' + req.customer_id;
                                                        error.time = getDateString();
                                                        error.status = 500;
                                                        error.index_in_transaction = 1;
                                                        error.display_message = dbErrorMessage;
                                                        next(error);
                                                    });
                                                }

                                                var checkProductString = squel.select({separator:"\n"})
                                                                            .from('products')
                                                                            .field('product_rating')
                                                                            .field('review_count')
                                                                            .where('product_id =?',
                                                                                req.params.product_id)
                                                                            .toString();

                                                // SELECT: select the product's rating and review count
                                                connection.query(checkProductString, 
                                                    function(error, results4, fields4){
                                                    if (error){
                                                        return connection.rollback(function(){
                                                            connection.release();
                                                            error.type = "connection.query";
                                                            error.identity = '[CUSTOMER]' + req.customer_id;
                                                            error.time = getDateString();
                                                            error.status = 500;
                                                            error.index_in_transaction = 2;
                                                            error.display_message = dbErrorMessage;
                                                            next(error);
                                                        });
                                                    }

                                                    var newRating = computeRating(results4[0].review_count,
                                                                                results4[0].product_rating,
                                                                                req.body.rating);

                                                    var updateString = squel.update({separator:"\n"})
                                                                            .table('products')
                                                                            .set('review_count = review_count + 1')
                                                                            .set('product_rating', newRating)
                                                                            .where('product_id =?', 
                                                                                req.params.product_id)
                                                                            .toString();

                                                    // UPDATE: update the product's rating and review count
                                                    connection.query(updateString, function(error, results5, fields5){
                                                        if (error){
                                                            return connection.rollback(function(){
                                                                connection.release();
                                                                error.type = "connection.query";
                                                                error.identity = '[CUSTOMER]' + req.customer_id;
                                                                error.time = getDateString();
                                                                error.status = 500;
                                                                error.index_in_transaction = 3;
                                                                error.display_message = dbErrorMessage;
                                                                next(error);
                                                            });
                                                        }

                                                        connection.commit(function(error){
                                                            if (error){
                                                                return connection.rollback(function(){
                                                                    connection.release();
                                                                    error.type = "connection.commit";
                                                                    error.identity = '[CUSTOMER]' + req.customer_id;
                                                                    error.time = getDateString();
                                                                    error.status = 500;
                                                                    error.display_message = dbErrorMessage;
                                                                    next(error);
                                                                });
                                                            }

                                                            connection.release();
                                                            res.status(200).json({
                                                                message: "리뷰 작성이 완료되었습니다",
                                                            });
                                                        });
                                                    });
                                                });
                                            });
                                        });
                                    }
                                }
                            });
                        }
                    }
                });

            }
        });
    }
});

// Vendor: verify user upon login request using hash function, provides token if success
router.post('/vendor/login', function(req, res, next){
    if (!req.body.username){
        res.status(401).json({
            error_message: "REQUIRED FIELDS: (username)",
            display_message: "아이디를 입력해 주세요."
        });
    } else if (!req.body.password){
        res.status(401).json({
            error_message: "REQUIRED FIELDS: (password)",
            display_message: "비밀번호를 입력해 주세요"
        });
    } else{

        pool.getConnection(function(error,connection){
            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }

                error.type = "pool.getConnection";
                error.identity = null;
                error.time = getDateString();
                error.status = 500;
                error.display_message = dbErrorMessage;
                next(error);
            } 
            
            else{
                var loginVendor = req.body;
                var queryString = squel.select({separator:"\n"})
                                    .field('vendor_password', 'password')
                                    .field('vendor_id', 'id')
                                    .field('vendor_name', 'name')
                                    .from('vendors')
                                    .where('vendor_username =?',loginVendor.username)
                                    .where('vendor_id = ?', loginVendor.vendor_id)
                                    .toString();

                // SELECT: fetch vendor's login data
                connection.query(queryString, function(error, results, fields){
                    connection.release();

                    if(error){
                        error.type = "connection.query";
                        error.identity = null;
                        error.time = getDateString();
                        error.status = 500;
                        error.query_index = 1;
                        error.display_message = serverErrorMessage;
                        next(error);
                    } 
                    
                    else{
                        // if the username(vendor) exists
                        if (!!results[0]){
                            var isValid = bcrypt.compareSync(loginVendor.password, results[0].password);
                        
                            // if the password is valid
                            if (isValid){
                                jwt.sign({vendor_username: loginVendor.username, vendor_id: results[0].id,
                                vendor_name: results[0].name},
                                process.env.USER_SECRET_KEY, {expiresIn: '7d'}, 
                                function(error, token){

                                    if (error){
                                        error.type = "jwt.sign";
                                        error.identity = null;
                                        error.time = getDateString();
                                        error.status = 500;
                                        error.display_message = loginErrorMessage;
                                        next(error);
                                    } 
                                    else{
                                        res.status(200).json({
                                            auth: true,
                                            token: token
                                        });
                                    }
                                });
                            } else {
                                res.status(401).json({
                                    status: "비밀번호가 일치하지 않습니다",
                                    auth: false,
                                    token: null
                                });
                            }
                        } else{
                            res.status(401).json({
                                status: "해당 아이디가 존재하지 않습니다",
                                auth: false,
                                token: null
                            });
                        }
                    }
                });
            }
        });
    }
});

// Vendor: register new vendor data using hash function
router.post('/vendor/register', function(req, res, next){
    if (!req.body.username || !req.body.password || !req.body.name || !req.body.password_confirm
        || !req.body.phone || !req.body.email){
        res.status(401).json({
            error_message: "REQUIRED FIELDS(username, password, password_confirm, name, phone, email)",
            display_message: "필수 항목을 모두 입력해 주세요"
        });
    } else if (req.body.username.length < 5 || req.body.username.length > 20){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 판매자 아이디(username)",
            display_message: "아이디가 5자 이상, 20자 이하이어야 합니다"
        });
    } else if (req.body.password.length < 6 || req.body.password.length > 16){
        res.status(401).json({
            error_messsage: "유효하지 않은 데이터: 판매자 비밀번호(password)",
            display_message: "비밀번호가 6자 이상, 16자 이하이어야 합니다"
        });
    } else if (req.body.password != req.body.password_confirm){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 판매자 비밀번호 확인(password_confirm)",
            display_message: "비밀번호와 비밀번호 확인이 일치하지 않습니다"
        });
    } else if (req.body.email.length > 30){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 판매자 이메일(email)",
            display_message: "이메일이 30자 이하여야 합니다."
        });
    } else if (req.body.phone.length > 15){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 판매자 전화번호(postal_code)",
            display_message: "전화번호가 15자 이하여야 합니다."
        });
    } else{

        pool.getConnection(function(error,connection){

            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }
                error.type = "pool.getConnection";
                error.identity = null;
                error.time = getDateString();
                error.status = 500;
                error.display_message = dbErrorMessage;
                next(error);
            } 
            else{
                connection.beginTransaction(function(error){
                    if (error){
                        connection.release();
                        error.type = "connection.beginTransaction";
                        error.identity = null;
                        error.time = getDateString();
                        error.status = 500;
                        error.display_message = dbErrorMessage;
                        next(error);
                    }

                    var newVendor = req.body;
                    var pwHash = bcrypt.hashSync(newVendor.password, 10);

                    var registerString = squel.insert({separator:"\n"})
                                            .into('vendors')
                                            .set('vendor_username', newVendor.username)
                                            .set('vendor_password', pwHash)
                                            .set('vendor_name', newVendor.name)
                                            .set('vendor_email', newVendor.email)
                                            .set('vendor_phone', newVendor.phone)
                                            .set('vendor_address_line1', newVendor.address1)
                                            .set('vendor_address_line2', newVendor.address2)
                                            .set('vendor_city', newVendor.city)
                                            .set('vendor_country', newVendor.country)
                                            .set('vendor_postal_code', newVendor.postal_code)
                                            .toString();

                    // INSERT: insert new vendor's data into vendors table
                    connection.query(registerString, function(error, results, fields){
                        if(error){
                            return connection.rollback(function() {
                                connection.release();
                                error.type = "connection.query";
                                error.identity = null;
                                error.time = getDateString();
                                error.status = 500;
                                error.index_in_transaction = 1
                                error.display_message = dbErrorMessage;
                                next(error);
                            });
                        }

                        var requestString = squel.select({separator:"\n"})
                                                .field('vendor_username')
                                                .field('vendor_name')
                                                .from('vendors')
                                                .where('vendor_id =?', results.insertId)
                                                .toString();
                        
                        // SELECT: check whether the data has been inserted
                        connection.query(requestString, function(error, results2, fields2){ 
                            if (error){
                                return connection.rollback(function() {
                                    connection.release();
                                    error.type = "connection.query";
                                    error.identity = null;
                                    error.time = getDateString();
                                    error.status = 500;
                                    error.index_in_transaction = 2;
                                    error.display_message = dbErrorMessage;
                                    next(error);
                                });
                            }
                            
                            var searchString = squel.select({separator:"\n"})
                                                    .field('MAX(rgt)', 'rgt')
                                                    .from('categories')
                                                    .toString();

                            connection.query(searchString, function(error, results3, fields3){
                                if (error){
                                    return connection.rollback(function(){
                                        connection.release();
                                        error.type = "connection.query";
                                        error.identity = null;
                                        error.time = getDateString();
                                        error.status = 500;
                                        error.index_in_transaction = 3;
                                        error.display_message = dbErrorMessage;
                                        next(error);
                                    });
                                }

                                var insertString = squel.insert({separator:"\n"})
                                                        .into('categories')
                                                        .set('vendor_id', results.insertId)
                                                        .set('category_name', 'vendor_' + results.insertId)
                                                        .set('lft', results3[0].rgt + 1)
                                                        .set('rgt', results3[0].rgt + 2)
                                                        .toString();
                                
                                // INSERT: insert new vendor's category into category table
                                connection.query(insertString, function(error, results4, fields4){
                                    if (error){
                                        return connection.rollback(function(){
                                            connection.release();
                                            error.type = "connection.query";
                                            error.identity = null;
                                            error.time = getDateString();
                                            error.status = 500;
                                            error.index_in_transaction = 4;
                                            error.display_message = dbErrorMessage;
                                            next(error);
                                        });
                                    }

                                    // if new vendor's data was properly inserted
                                    if (!!results2) {
                                        jwt.sign({vendor_username: results2[0].vendor_username, 
                                        vendor_id: results.insertId, vendor_name: results2[0].vendor_name},
                                        process.env.USER_SECRET_KEY, {expiresIn: '7d'}, 
                                        function(error, token){

                                            if (error){
                                                return connection.rollback(function(){
                                                    connection.release();
                                                    error.type = "jwt.sign";
                                                    error.identity = null;
                                                    error.time = getDateString();
                                                    error.status = 500;
                                                    error.display_message = loginErrorMessage;
                                                    next(error);
                                                });
                                            }

                                            connection.commit(function(error){
                                                if (error){
                                                    return connection.rollback(function(){
                                                        connection.release();
                                                        error.type = "connection.commit";
                                                        error.identity = null;
                                                        error.time = getDateString();
                                                        error.status = 500;
                                                        error.display_message = dbErrorMessage;
                                                        next(error);
                                                    });
                                                }

                                                connection.release();
                                                res.status(200).json({
                                                    message: "회원가입이 완료되었습니다",
                                                    auth: true,
                                                    token: token
                                                });
                                            });
                                        });
                                    } 
                                    // if not inserted
                                    else{
                                        res.status(500).json({
                                            error_message: "데이터 베이스에 정보가 등록되지 않았습니다",
                                            display_message: "알 수 없는 오류"
                                        });
                                    }
                                });
                            });
                        });
                    });
                });
            }
        });
    }
});

// Vendor: change password once login-ed
router.put('/vendor/register', verifyVendorToken, function(req, res, next){
    if (!req.body.password || !req.body.new_password || !req.body.new_password_confirm){
        res.status(401).json({
            error_message: "REQUIRED FIELDS (password, new_password, new_password_confirm",
            display_message: "필수 항목을 모두 입력해 주세요"
        });
    } else if (req.body.password == req.body.new_password){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 판매자 새 비밀번호 (new_password)",
            display_message: "새 비밀번호를 현재 비밀번호와 다르게 설정하세요"
        });
    } else if (req.body.new_password != req.body.new_password_confirm){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 판매자 새 비밀번호 확인 (new_password_confirm)",
            display_message: "새 비밀번호가 일치하지 않습니다"
        });
    } else if (req.body.new_password.length < 6 || req.body.new_password.length > 16){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 판매자 새 비밀번호 (new_password)",
            display_message: "새 비밀번호를 6자 이상, 16자 이하로 설정해 주세요"
        });
    } else{

        pool.getConnection(function(error,connection){

            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }

                error.type = "pool.getConnection";
                error.identity = '[VENDOR]' + req.vendor_id;
                error.time = getDateString();
                error.status = 500;
                error.display_message = dbErrorMessage;
                next(error);
            } 
            else{
                var queryString = squel.select({separator:"\n"})
                                    .from('vendors')
                                    .field('vendor_password', 'password')
                                    .where('vendor_id = ?', req.vendor_id)
                                    .toString();

                // SELECT: fetch vendor's original password (hashed)
                connection.query(queryString, function(error, results, fields){
                    if (error){
                        connection.release();
                        error.type = "connection.query";
                        error.identity = '[VENDOR]' + req.vendor_id;
                        error.time = getDateString();
                        error.status = 500;
                        error.query_index = 1;
                        error.display_message = serverErrorMessage;
                        next(error);
                    } 
                    
                    else{
                        var isValid = bcrypt.compareSync(req.body.password, results[0].password);

                        // if the old password doesn't match
                        if (!isValid){
                            connection.release();
                            res.status(401).json({
                                message: '입력하신 비밀번호가 일치하지 않습니다'
                            });
                        }
                        // if matches
                        else { 
                            var newPwHashed = bcrypt.hashSync(req.body.new_password, 10);
                            var changeQuery = squel.update({separator:"\n"})
                                                .table('vendors')
                                                .set('vendor_password', newPwHashed)
                                                .where('vendor_id = ?', req.vendor_id)
                                                .toString();

                            // UPDATE: update vendor's data with new password(hashed)
                            connection.query(changeQuery, function(error, results2, fields2){
                                connection.release();

                                if (error){
                                    error.type = "connection.query";
                                    error.identity = '[VENDOR]' + req.vendor_id;
                                    error.time = getDateString();
                                    error.status = 500;
                                    error.query_index = 2;
                                    error.display_message = serverErrorMessage;
                                    next(error);
                                } else{
                                    res.status(200).json({
                                        message: "비밀번호가 성공적으로 변경되었습니다"
                                    });
                                }
                            });
                        }
                    }
                });
            }
        });
    }
});

// Vendor: Add new product
router.post('/vendor/add_product', verifyVendorToken, function(req, res, next){ 
    if (!req.body.name || !req.body.category_id || !req.body.stock_quantity || !req.body.price_original){
        res.status(401).json({
            error_message: "REQUIRED FIELDS : (name, category_id, stock_quantity, price_original)",
            display_message: "필수 항목을 모두 입력해 주세요"
        });
    } else if (req.body.name.length > 20){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 상품 이름 (name)",
            display_message: "상품 이름이 20자 이하여야 합니다"
        });
    } else if (req.body.stock_quantity < 0){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 상품 재고 (stock_quantity)",
            display_message: "상품 재고는 0개 이상이어야 합니다"
        });
    } else if (req.body.price_original < 0){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 상품 가격 (price_original)",
            display_message: "상품 가격이 0원 이상이어야 합니다"
        });
    } else if (req.body.price_discounted && (req.body.price_discounted >= req.body.price_original)){
        res.status(401).json({
            error_message: "유효하지 않은 데이터: 상품 할인 가격 (price_discounted)",
            display_message: "해당 상품의 할인 가격이 원래 가격보다 낮아야 합니다"
        });
    } else{

        pool.getConnection(function(error,connection){

            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }

                error.type = "pool.getConnection";
                error.identity = '[VENDOR]' + req.vendor_id;
                error.time = getDateString();
                error.status = 500;
                error.display_message = dbErrorMessage;
                next(error);
            } 
            else{
                var newProduct = req.body;
                var queryString = squel.insert({separator:"\n"})
                                    .into('products')
                                    .set('product_name', newProduct.name)
                                    .set('category_id', newProduct.category_id)
                                    .set('vendor_id', req.vendor_id)
                                    .set('stock_quantity', newProduct.stock_quantity)
                                    .set('price_original', newProduct.price_original)
                                    .set('price_discounted', newProduct.price_discounted)
                                    .set('tag', newProduct.tag)
                                    .set('product_description', newProduct.description)
                                    .toString();

                // INSERT: add new product's data into product table
                connection.query(queryString, function(error, results, fields){
                    connection.release();

                    if(error){
                        error.type = "connection.query";
                        error.identity = '[VENDOR]' + req.vendor_id;
                        error.time = getDateString();
                        error.status = 500;
                        error.query_index = 1;
                        error.display_message = serverErrorMessage;
                        next(error);
                    }else{
                        res.status(200).json({
                            message: "성공적으로 새 상품을 등록하였습니다.",
                            results,
                            fields
                        });
                        
                    }
                });
            }
        });
    }
});

// Vendor: add new category
router.post('/vendor/add_category', verifyVendorToken, function(req, res, next){
    if (!req.body.category_name){
        res.status(401).json({
            error_message: "REQUIRED FIELDS: (category_name)",
            display_message: "카테고리 이름을 입력해 주세요"
        });
    } else if (req.body.category_name.length > 20){
        res.status(401).json({
            error_message: "유효하지 않은 데이터 : (category_name)",
            display_message: "카테고리 이름은 20자 이하여야 합니다"
        });
    } else{

        pool.getConnection(function(error,connection){

            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }

                error.type = "pool.getConnection";
                error.identity = '[VENDOR]' + req.vendor_id;
                error.time = getDateString();
                error.status = 500;
                error.display_message = dbErrorMessage;
                next(error);
            } 
            else{
                var newCategory = req.body;
                var queryString;

                // if no parent_id was given (= add largest main category)
                if (!newCategory.parent_id){
                    queryString = squel.select({separator:"\n"})
                                    .from('categories')
                                    .field('MIN(lft)', 'lft')
                                    .field('MAX(rgt)', 'rgt')
                                    .field('category_id')
                                    .field('vendor_id')
                                    .where('vendor_id =?', req.vendor_id)
                                    .toString();
                }
                // if create a subcategory within an existing category
                else{
                    queryString = squel.select({separator:"\n"})
                                    .from('categories')
                                    .field('lft')
                                    .field('rgt')
                                    .field('vendor_id')
                                    .where('category_id =?', newCategory.parent_id)
                                    .toString();
                }

                // SELECT: select the appropirate rgt value
                connection.query(queryString, function(error, results, fields){
                    if (error){
                        connection.release();
                        error.type = "connection.query";
                        error.identity = '[VENDOR]' + req.vendor_id;
                        error.time = getDateString();
                        error.status = 500;
                        error.query_index = 1;
                        error.display_message = serverErrorMessage;
                        next(error);
                    }

                    // if another vendor's category was selected
                    if (req.vendor_id != results[0].vendor_id) {
                        connection.release();
                        res.status(500).json({
                            error_message: "Invalid data: parent_id",
                            display_message: "알 수 없는 오류가 발생하였습니다"
                        });
                    } 

                    else{
                        connection.beginTransaction(function(error) {
                            if (error){
                                connection.release();
                                error.type = "connection.beginTransaction";
                                error.identity = '[VENDOR]' + req.vendor_id;
                                error.time = getDateString();
                                error.status = 500;
                                error.display_message = dbErrorMessage;
                                next(error);
                            }

                            var lftUpdateQuery = squel.update({separator:"\n"})
                                                    .table('categories')
                                                    .set('lft = lft + 2')
                                                    .where('lft > ?', results[0].rgt)
                                                    .toString();

                            // UPDATE: update lft values of categories
                            connection.query(lftUpdateQuery, function(error, results2, fields2){
                                if (error){
                                    return connection.rollback(function(){
                                        connection.release();
                                        error.type = "connection.query";
                                        error.identity = '[VENDOR]' + req.vendor_id;
                                        error.time = getDateString();
                                        error.status = 500;
                                        error.index_in_transaction = 1;
                                        error.display_message = dbErrorMessage;
                                        next(error);
                                    });
                                }

                                var rgtUpdateQuery = squel.update({separator:"\n"})
                                                        .table('categories')
                                                        .set('rgt = rgt + 2')
                                                        .where('rgt > ?', (results[0].rgt-1))
                                                        .toString();

                                // UPDATE: update rgt values of categories
                                connection.query(rgtUpdateQuery, function(error, results3, fields3){
                                    if (error){
                                        return connection.rollback(function(){
                                            connection.release();
                                            error.type = "connection.query";
                                            error.identity = '[VENDOR]' + req.vendor_id;
                                            error.time = getDateString();
                                            error.status = 500;
                                            error.index_in_transaction = 2;
                                            error.display_message = serverErrorMessage;
                                            next(error);
                                        });
                                    }

                                    // if parent id was not given, set it to the vendor's category_id
                                    if (!newCategory.parent_id){
                                        newCategory.parent_id = results[0].category_id;
                                    }

                                    var insertQuery = squel.insert({separator:"\n"})
                                                        .into('categories')
                                                        .set('vendor_id', req.vendor_id)
                                                        .set('parent_id', newCategory.parent_id)
                                                        .set('category_name', newCategory.category_name)
                                                        .set('lft', results[0].rgt)
                                                        .set('rgt', results[0].rgt + 1)
                                                        .toString();

                                    // INSERT: insert new category with appropriate lft and rgt values
                                    connection.query(insertQuery, function(error, results4, fields4){
                                        if (error){
                                            return connection.rollback(function() {
                                                connection.release();
                                                error.type = "connection.query";
                                                error.identity = '[VENDOR]' + req.vendor_id;
                                                error.time = getDateString();
                                                error.status = 500;
                                                error.index_in_transaction = 3;
                                                error.display_message = dbErrorMessage;
                                                next(error);
                                            });
                                        }
                                
                                        connection.commit(function(error){
                                            if (error){
                                                return connection.rollback(function() {
                                                    connection.release();
                                                    error.type = "connection.commit";
                                                    error.identity = '[VENDOR]' + req.vendor_id;
                                                    error.time = getDateString();
                                                    error.status = 500;
                                                    error.display_message = dbErrorMessage;
                                                    next(error);
                                                });
                                            }
                                    
                                            connection.release();
                                            res.status(200).json({
                                                message: "성공적으로 카테고리가 추가되었습니다"
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    }
                });
            }
        });
    }
});

// Vendor: delete category
router.delete('/vendor/delete_category', verifyVendorToken, function(req, res, next){
    pool.getConnection(function(error,connection){

        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }

            error.type = "pool.getConnection";
            error.identity = '[VENDOR]' + req.vendor_id;
            error.time = getDateString();
            error.status = 500;
            error.display_message = dbErrorMessage;
            next(error);
        } 
        else{
            var queryString = squel.select({separator:"\n"})
                                   .from('categories')
                                   .field('lft')
                                   .field('rgt')
                                   .where('category_id =?', req.body.category_id)
                                   .toString();

            // SELECT: fetch lft and rgt values of the category to delete
            connection.query(queryString, function(error, results, fields){
                if (error){
                    connection.release();
                    error.type = "connection.query";
                    error.identity = '[VENDOR]' + req.vendor_id;
                    error.time = getDateString();
                    error.status = 500;
                    error.query_index = 1;
                    error.display_message = serverErrorMessage;
                    next(error);
                } 
                else{
                    var diff = results[0].rgt - results[0].lft;

                    // if the category has no subcategory inside it
                    if (diff == 1){
                        connection.beginTransaction(function(error){
                            if (error){
                                connection.release();
                                error.type = "connection.beginTransaction";
                                error.identity = '[VENDOR]' + req.vendor_id;
                                error.time = getDateString();
                                error.status = 500;
                                error.display_message = dbErrorMessage;
                                next(error);
                            }

                            var deleteString = squel.delete({separator:"\n"})
                                                    .from('categories')
                                                    .where('category_id =?', req.body.category_id)
                                                    .toString();

                            // DELETE: delete the category
                            connection.query(deleteString, function(error, results2, fields2){
                                if (error){
                                    return connection.rollback(function() {
                                        connection.release();
                                        error.type = "connection.query";
                                        error.identity = '[VENDOR]' + req.vendor_id;
                                        error.time = getDateString();
                                        error.status = 500;
                                        error.index_in_transaction = 1;
                                        error.display_message = dbErrorMessage;
                                        next(error);
                                    });
                                }

                                var lftUpdateString = squel.update({separator:"\n"})
                                                        .table('categories')
                                                        .set('lft = lft - 2')
                                                        .where('lft > ?', results[0].rgt)
                                                        .toString();

                                // UPDATE: update lft values of categories
                                connection.query(lftUpdateString, function(error, results3, fields3){
                                    if (error){
                                        return connection.rollback(function(){
                                            connection.release();
                                            error.type = "connection.query";
                                            error.identity = '[VENDOR]' + req.vendor_id;
                                            error.time = getDateString();
                                            error.status = 500;
                                            error.index_in_transaction = 2;
                                            error.display_message = dbErrorMessage;
                                            next(error);
                                        });
                                    }

                                    var rgtUpdateString = squel.update({separator:"\n"})
                                                               .table('categories')
                                                               .set('rgt = rgt - 2')
                                                               .where('rgt > ?', results[0].rgt)
                                                               .toString();

                                    // UPDATE: update rgt values of categories
                                    connection.query(rgtUpdateString, function(error, results4, fields4){
                                        if (error){
                                            return connection.rollback(function(){
                                                connection.release();
                                                error.type = "connection.query";
                                                error.identity = '[VENDOR]' + req.vendor_id;
                                                error.time = getDateString();
                                                error.status = 500;
                                                error.index_in_transaction = 3;
                                                error.display_message = dbErrorMessage;
                                                next(error);
                                            });
                                        }

                                        connection.commit(function(error){
                                            if (error){
                                                return connection.rollback(function() {
                                                    connection.release();
                                                    error.type = "connection.commit";
                                                    error.identity = '[VENDOR]' + req.vendor_id;
                                                    error.time = getDateString();
                                                    error.status = 500;
                                                    error.display_message = dbErrorMessage;
                                                    next(error);
                                                });
                                            }
                                    
                                            connection.release();
                                            res.status(200).json({
                                                message: "성공적으로 카테고리가 제거되었습니다"
                                            });
                                        });
                                    })
                                });
                            });
                        });
                    } 
                    // if the category DOES have subcategories
                    else{
                        connection.release();
                        res.status(401).json({
                            message: "하위 카테고리를 모두 삭제하셔야 합니다"
                        });
                    }
                }
            });
        }
    });
});

// Vendor: upload product images
router.post('/vendor/upload_images', verifyVendorToken, upload.array('photo', 3), function(req, res, next) {
    pool.getConnection(function(error,connection){

        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }

            error.type = "pool.getConnection";
            error.identity = '[VENDOR]' + req.vendor_id;
            error.time = getDateString();
            error.status = 500;
            error.display_message = dbErrorMessage;
            next(error);
        } 
        else{
            var photosArray = [];

            for (i = 0; i < req.files.length; i++){
                photosArray.push({product_id: req.body.product_id,
                                  image_pathname: req.files[i].key});
            }

            var uploadString = squel.insert({separator:"\n"})
                                    .into('product_images')
                                    .setFieldsRows(photosArray)
                                    .toString();

            // INSERT: insert pathnames and product_id of the inserted images
            connection.query(uploadString, function(error, results, fields){
                connection.release();

                if (error){
                    error.type = "connection.query";
                    error.identity = '[VENDOR]' + req.vendor_id;
                    error.time = getDateString();
                    error.status = 500;
                    error.query_index = 1;
                    error.display_message = serverErrorMessage;
                    next(error);
                } else{
                    res.status(200).json({
                        message: "이미지가 성공적으로 추가되었습니다"
                    });
                }
            });
        }
    });
});

// Function for verifying customer's token
function verifyToken(req, res, next){
    var bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined'){
        var bearer = bearerHeader.split(" ");
        var bearerToken = bearer[1];
        jwt.verify(bearerToken, process.env.USER_SECRET_KEY, function(error, decoded) {
            if (error){ 
                res.status(403).json({ 
                    auth: false, 
                    token: null
                });  
            } else{
                req.username = decoded["username"];
                req.customer_id = decoded["customer_id"];
                req.full_name = decoded["full_name"];
                req.vendor_id = decoded["vendor_id"];
                next();
            }
        });	
    } else{
        res.status(403).json({
            auth:false, 
            token:null
        });
    }
}

// Function for verifying vendor's token
function verifyVendorToken(req, res, next){
    var bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined'){
        var bearer = bearerHeader.split(" "); 
        var bearerToken = bearer[1];
        jwt.verify(bearerToken, process.env.USER_SECRET_KEY, function(error, decoded) {
            if (error) {
                res.status(403).json({ auth: false, 
                    message: 'Authentication Token Invalid: 입력하신 토큰이 유효하지 않습니다.'});    
            } else{
                req.vendor_username = decoded["vendor_username"];
                req.vendor_id = decoded["vendor_id"];
                req.vendor_name = decoded["vendor_name"];
                next();
            }
        });	
    } else{
        res.status(403).json({
            auth:false, 
            token:null
        });
    }
}

// function for generating current time in string
function getDateString(){
    var datetimenow = new Date(Date.now());
    var year = datetimenow.getUTCFullYear();
    var month = datetimenow.getUTCMonth()+1;
    var date = datetimenow.getUTCDate();

    var hour = datetimenow.getUTCHours();
    var minute = datetimenow.getUTCMinutes();
    var second = datetimenow.getUTCSeconds();
    var dateString = year + "-" + month + "-" + date + " " + hour + ":" + minute + ":" + second;
    return dateString;
}

// Function for generating current time in string
function getDateSerial(){
	var datetimenow = new Date(Date.now());
	var year = datetimenow.getFullYear();
	var month = datetimenow.getMonth()+1;
	var date = datetimenow.getDate();

	var hour = datetimenow.getHours();
	var minute = datetimenow.getMinutes();
	var second = datetimenow.getSeconds();
	return ""+year+month+date+hour+minute+second;
}

function computeRating(count, oldRating, newRating){
    return ((count * oldRating) + newRating) / (count + 1)
}

router.use(function(error, req, res, next){    
    //This is the router error handler
    //API안에서 발생한 connection error, 뭐 등등으로 여기에다 잡스럽게 떨어질거다.
    /* 
    common type errors 1. pool.getConnection error.
                       2. common type errors.
                       3. 그외에 runtime error
    
    
    
    */
    error.params = req.params
    error.body = req.body;
    error.route = req.route;
    error.originalUrl = req.originalUrl;
    next(error);
    
});

module.exports = router;