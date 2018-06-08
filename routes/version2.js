require('dotenv/config');
const express = require('express');
const router = express.Router();
const pool = require('../db2.js');
const squel = require('squel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// image upload
const AWS = require('aws-sdk');
const multer = require('multer');
const multerS3 = require('multer-s3');

const BUCKET_NAME = process.env.AWS_S3_BUCKET_NAME || 'shopapp-img';
const IAM_USER_KEY = process.env.IAM_USER_KEY;
const IAM_USER_SECRET = process.env.IAM_USER_SECRET;


const s3bucket = new AWS.S3({
    accessKeyId: IAM_USER_KEY,
    secretAccessKey: IAM_USER_SECRET,
    Bucket: BUCKET_NAME
});


const upload = multer({
    storage: multerS3({
        s3: s3bucket,
        bucket: 'shopapp-img',
        acl: 'public-read',
        contentType: function(req, file, cb){
            cb(null, file.mimetype);    
        },
        metadata: function (req, file, cb) {
            cb(null, {fieldName: file.fieldname, 'Content-Type': file.mimetype, 'Cache_control': 'public, max-age=31536000'});
        },
        key: function (req, file, cb) {
            if(req.customer_id == undefined && req.vendor_id){
                cb(null, file.fieldname+ "/VENDOR"+ req.vendor_id + "_" +  getDateSerial()) 
            }else if(req.vendor_id == undefined && req.customer_id){
                cb(null, file.fieldname+ "/"+ req.username + "_" +  getDateSerial()) 
            }else{
                cb(null, file.fieldname+ "/ANON_" +  getDateSerial()) 
            }
        }
    })
});


//sample upload using multer route adjusted to shopapp
router.post('/upload', upload.array('photo', 3), function(req, res, next) {
    for(index in req.files){
        console.log(req.files[index]);
    }
    res.status(200).json({
        result: req.body
    });
})

//NO INSERT
router.post('/api/login', function(req, res){
    if (!req.body.username || !req.body.password){
        res.status(401).json({
            error_message: "REQUIRED FIELDS : (username, password)",
            user_error_message: "필수 항목을 모두 입력하십시오."
        });
    }
    else if(req.body.username.length > 20 || req.body.username.length < 4 || req.body.password.length > 20 ||  req.body.password.length < 4){
        res.status(401).json({
            error_type: "Data Integrity Violation",
            error_message: "입력하신 파라미터 글자 숫자를 참고하세요: username(4~20), password(4~20)"
        });
    }
    else{
        pool.getConnection(function(error, connection){
            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }
                next(error);
            }
            else{
                var queryString = squel.select({separator: "\n"})
                                    .from('customers')
                                    .field('customer_id')
                                    .field('password')
                                    .field('customer_last_name')
                                    .field('customer_first_name')
                                    .where('username = ?', req.body.username)
                                    .toString();
                connection.query(queryString, function(error, results, fields){
                    connection.release();
                    if (error){
                        next(error);
                    } 
                    else{
                        if (!!results[0]){
                            var password_stored = results[0].password;
                            var passwordIsValid = bcrypt.compareSync(req.body.password, password_stored);
                            if (passwordIsValid){
                                jwt.sign({username: req.body.username, customer_id: results[0].customer_id, customer_first_name: results[0].customer_first_name}, process.env.USER_SECRET_KEY, {expiresIn: '7d'}, function(error, token){
                                    if (error){
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
                            else{
                                res.status(401).json({
                                    status: "id / 비밀번호가 일치 하지 않습니다.",
                                    auth: false,
                                    token: null
                                });
                            }
                        }
                        else{
                            res.status(401).json({
                                status: "해당 아이디가 존재 하지 않습니다.",
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

//ONE INSERT
router.post('/api/register', function(req, res){
    /*
    {
        "username":
        "password":
        "customer_last_name":
        "customer_first_name":
        "customer_email":
        "customer_phone":
        "address_line1":
        "address_line2": (optional)
        "city":
        "postal_code":
        "country":
    }
    */
    if(!req.body.username || !req.body.password || !req.body.customer_last_name || !req.body.customer_first_name  || !req.body.customer_phone || !req.body.customer_address_line1 || !req.body.customer_city ||
        !req.body.customer_postal_code || !req.body.customer_country){
        res.status(401).json({
            error_message: "REQUIRED FIELDS : (username, password, customer_last_name, customer_first_name, customer_phone, customer_address_line1, customer_city, customer_postal_code, customer_country)",
            user_error_message: "필수 항목을 모두 입력하십시오."
        });
    }else if(req.body.username.length < 4 || req.body.username.length > 20 || req.body.password.length < 4 || req.body.password.length > 20 ||
                req.body.customer_phone.length > 20 || req.body.customer_email.length > 30){
        res.status(401).json({
            error_type: "Data Integrity Violation",
            error_message: "입력하신 파라미터 글자 숫자를 참고하세요: username(4~20), password(4~20), phone(~20), email(~30)"
        });
    }
    else{
        pool.getConnection(function(error, connection){
            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }
                next(error);
            }
            else{
                var hashedPassword = bcrypt.hashSync(req.body.password, parseInt(process.env.SALT_ROUNDS));
                console.log(hashedPassword);
                // var clean_phone_number = req.body.phone_number.replace(/-/g,'');
                var queryString = squel.insert({separator: "\n"})
                                       .into('customers')
                                       .set('username', req.body.username)
                                       .set('password', hashedPassword)
                                       .set('customer_last_name', req.body.customer_last_name)
                                       .set('customer_first_name', req.body.customer_first_name)
                                       .set('customer_email', req.body.email)
                                       .set('customer_phone', req.body.phone)
                                       .set('customer_address_line1', req.body.address_line1)
                                       .set('customer_address_line2', req.body.address_line2)
                                       .set('customer_city', req.body.city)
                                       .set('customer_postal_code', req.body.postal_code)
                                       .set('customer_country', req.body.country)
                                       .toString();
                connection.query(queryString, function(error, results, fields){
                    connection.release();
                    if (error){
                        next(error);    
                    }
                    else{
                        jwt.sign({username: req.body.username, customer_id: results.customer_id, customer_first_name: req.body.customer_first_name}, process.env.USER_SECRET_KEY, {expiresIn: '7d'}, function(error, token){
                            if (error){
                                next(error);
                            }
                            else{
                                res.status(200).json({
                                    auth: true,
                                    token: token,
                                    results: results
                                });
                            }
                        });
                    }   
                });
            }
        });
    }   
});

//NO INSERT
router.post('/api/vendor/login', function(req, res){
    if (!req.body.vendor_username || !req.body.vendor_password){
        res.status(401).json({
            error_message: "REQUIRED FIELDS : (username, password)",
            user_error_message: "필수 항목을 모두 입력하십시오."
        });
    }
    else if(req.body.vendor_username.length > 20 || req.body.vendor_username.length < 4 || req.body.vendor_password.length > 20 ||  req.body.vendor_password.length < 4){
        res.status(401).json({
            error_type: "Data Integrity Violation",
            error_message: "입력하신 파라미터 글자 숫자를 참고하세요: vendor_username(4~20), password(4~20)"
        });
    }
    else{
        pool.getConnection(function(error, connection){
            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }
                next(error);
            }
            else{
                var queryString = squel.select({separator: "\n"})
                                    .from('vendors')
                                    .field('vendor_id')
                                    .field('vendor_password')
                                    .field('vendor_name')
                                    .where('vendor_username = ?', req.body.vendor_username)
                                    .toString();
                connection.query(queryString, function(error, results, fields){
                    connection.release();
                    if (error){
                        next(error);
                    } 
                    else{
                        if (!!results[0]){
                            console.log(results[0]);
                            var password_stored = results[0].vendor_password;
                            console.log(password_stored);
                            var passwordIsValid = bcrypt.compareSync(req.body.vendor_password, password_stored);
                            if (passwordIsValid){
                                jwt.sign({vendor_username: req.body.vendor_username, vendor_id: results[0].vendor_id, vendor_name: results[0].vendor_name}, process.env.VENDOR_SECRET_KEY, {expiresIn: '7d'}, function(error, token){
                                    if (error){
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
                            else{
                                res.status(401).json({
                                    status: "id / 비밀번호가 일치 하지 않습니다.",
                                    auth: false,
                                    token: null
                                });
                            }
                        }
                        else{
                            res.status(401).json({
                                status: "해당 아이디가 존재 하지 않습니다.",
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
router.post('/api/vendor/register', function(req, res, next){

    if(!req.body.vendor_username || !req.body.vendor_password ||  !req.body.vendor_name ||
        !req.body.vendor_email || !req.body.vendor_phone || !req.body.vendor_address_line1 || !req.body.vendor_city ||
        !req.body.vendor_postal_code || !req.body.vendor_country){
        res.status(401).json({
            error_message: "REQUIRED FIELDS : (vendor_username, vendor_password, vendor_name, vendor_email, vendor_phone, vendor_address_line1, vendor_city, vendor_postal_code, vendor_country)",
            user_error_message: "필수 항목을 모두 입력하십시오."
        });
    }else if(req.body.vendor_username.length < 4 || req.body.vendor_username.length > 20 || req.body.vendor_password.length < 4 || req.body.vendor_password.length > 20 ||
                req.body.vendor_phone.length > 20 || req.body.vendor_email.length > 30){
        res.status(401).json({
            error_type: "Data Integrity Violation",
            error_message: "입력하신 파라미터 글자 숫자를 참고하세요: vendor_username(4~20), vendor_password(4~20), vendor_phone(~20), vendor_email(~30)"
        });
    }

    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            connection.beginTransaction(function(err){
                if (error){
                    connection.release();
                    next(error);
                }
                var hashedPassword = bcrypt.hashSync(req.body.vendor_password, parseInt(process.env.SALT_ROUNDS));
                var registerString = squel.insert({separator:"\n"})
                                         .into('vendors')
                                         .set('vendor_username', req.body.vendor_username)
                                         .set('vendor_password', hashedPassword)
                                         .set('vendor_name', req.body.vendor_name)
                                         .set('vendor_email', req.body.vendor_email)
                                         .set('vendor_phone', req.body.vendor_phone)
                                         .set('vendor_address_line1', req.body.vendor_address_line1)
                                         .set('vendor_address_line2', req.body.vendor_address_line2)
                                         .set('vendor_city', req.body.vendor_city)
                                         .set('vendor_country', req.body.vendor_country)
                                         .set('vendor_postal_code', req.body.vendor_postal_code)
                                         .toString();
                connection.query(registerString, function(error, results, fields){
                    if(error){
                        return connection.rollback(function() {
                            connection.release();
                            next(error);
                        });
                    }

                    var requestString = squel.select({seperator:"\n"})
                                            .from('vendors')
                                            .field('vendor_username')
                                            .field('vendor_name')
                                            .where('vendor_id =?', results.insertId)
                                            .toString();
                    
                    connection.query(requestString, function(error2, results2, fields2){ 
                        if (error2){
                            return connection.rollback(function() {
                                connection.release();
                                next(error2);
                            });
                        }
                        
                        var searchString = squel.select({seperator:"\n"})
                                                .from('categories')
                                                .field('MAX(rgt)', 'rgt')
                                                .toString();
                        
                        connection.query(searchString, function(error3, results3, fields3){
                            if (error3){
                                return connection.rollback(function(){
                                    connection.release();
                                    next(error3);
                                });
                            }

                            var insertString = squel.insert({seperator:"\n"})
                                                    .into('categories')
                                                    .set('vendor_id', results.insertId)
                                                    .set('category_name', 'vendor_' + results.insertId)
                                                    .set('lft', results3[0].rgt + 1)
                                                    .set('rgt', results3[0].rgt + 2)
                                                    .toString();
                            
                            connection.query(insertString, function(error4, results4, fields4){
                                if (error4){
                                    return connection.rollback(function(){
                                        connection.release();
                                        next(error4);
                                    });
                                }
                                if (!!results2) {
                                    jwt.sign({vendor_username: results2[0].vendor_username, 
                                    vendor_id: results.insertId, vendor_name: results2[0].vendor_name},
                                    process.env.VENDOR_SECRET_KEY, {expiresIn: '7d'}, 
                                    function(error, token){
                                        if (error){
                                            return connection.rollback(function(){
                                                connection.release();
                                                next(error);
                                            });
                                        }
                                        connection.commit(function(err){
                                            if (error){
                                                return connection.rollback(function(){
                                                    connection.release();
                                                    next(error);
                                                });
                                            }
                                            connection.release();
                                            res.status(200).json({
                                                message: "회원가입이 완료되었습니다.",
                                                auth: true,
                                                token: token
                                            });
                                        });
                                    });
                                } else{
                                    connection.release();
                                    res.status(401).json({
                                        message: "Internal Server Error: Registration Failed"
                                    });
                                }
                            });
                        });
                    });
                });
            });
        }
    });
});

//ONE INSERT
router.post('/api/vendor/register', function(req, res, next){

    if(!req.body.vendor_username || !req.body.vendor_password ||  !req.body.vendor_name ||
        !req.body.vendor_email || !req.body.vendor_phone || !req.body.vendor_address_line1 || !req.body.vendor_city ||
        !req.body.vendor_postal_code || !req.body.vendor_country){
        res.status(401).json({
            error_message: "REQUIRED FIELDS : (vendor_username, vendor_password, vendor_name, vendor_email, vendor_phone, vendor_address_line1, vendor_city, vendor_postal_code, vendor_country)",
            user_error_message: "필수 항목을 모두 입력하십시오."
        });
    }else if(req.body.vendor_username.length < 4 || req.body.vendor_username.length > 20 || req.body.vendor_password.length < 4 || req.body.vendor_password.length > 20 ||
                req.body.vendor_phone.length > 20 || req.body.vendor_email.length > 30){
        res.status(401).json({
            error_type: "Data Integrity Violation",
            error_message: "입력하신 파라미터 글자 숫자를 참고하세요: vendor_username(4~20), vendor_password(4~20), vendor_phone(~20), vendor_email(~30)"
        });
    }
    else{
        pool.getConnection(function(error, connection){
            if(error){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }
                next(error);
            }
            else{
                var hashedPassword = bcrypt.hashSync(req.body.vendor_password, parseInt(process.env.SALT_ROUNDS));
                // var clean_phone_number = req.body.phone_number.replace(/-/g,'');
                var queryString = squel.insert({separator: "\n"})
                                       .into('vendors')
                                       .set('vendor_username', req.body.vendor_username)
                                       .set('vendor_password', hashedPassword)
                                       .set('vendor_name', req.body.vendor_name)
                                       .set('vendor_email', req.body.vendor_email)
                                       .set('vendor_phone', req.body.vendor_phone)
                                       .set('vendor_address_line1', req.body.vendor_address_line1)
                                       .set('vendor_address_line2', req.body.vendor_address_line2)
                                       .set('vendor_city', req.body.vendor_city)
                                       .set('vendor_postal_code', req.body.vendor_postal_code)
                                       .set('vendor_country', req.body.vendor_country)
                                       .toString();
                connection.query(queryString, function(error, results, fields){
                    connection.release();
                    if (error){
                        next(error);    
                    }
                    else{
                        jwt.sign({vendor_username: req.body.vendor_username, vendor_id: results.vendor_id, vendor_name: req.body.vendor_name}, process.env.VENDOR_SECRET_KEY, {expiresIn: '7d'}, function(error, token){
                            if (error){
                                next(error);
                            }
                            else{
                                res.status(200).json({
                                    auth: true,
                                    token: token,
                                    results: results
                                });
                            }
                        });
                    }   
                });
            }
        });
    }   
});



// [from v1] Vendor: add new category
router.post('/api/vendor/add_category', verifyVendorToken, function(req, res, next){
    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var newCategory = req.body;
            console.log(req.body);
            var queryString;
            if (!newCategory.parent_id){
                queryString = squel.select({seperator:"\n"})
                                   .from('categories')
                                   .field('MIN(lft)', 'lft')
                                   .field('MAX(rgt)', 'rgt')
                                   .where('vendor_id = ?', req.vendor_id)
                                   .toString();
            } else{
                queryString = squel.select({seperator:"\n"})
                                   .from('categories')
                                   .field('lft')
                                   .field('rgt')
                                   .where('category_id = ?', newCategory.parent_id)
                                   .toString();
            }

            connection.query(queryString, function(error, results, fields){
                if (error){
                    connection.release();
                    next(error);
                }
                connection.beginTransaction(function(error) {
                    if (error){
                        connection.release();
                        next(error);
                    }
                    var lftUpdateQuery = squel.update({seperator:"\n"})
                                              .table('categories')
                                              .set('lft = lft + 2')
                                              .where('lft > ?', results[0].rgt)
                                              .toString();

                    connection.query(lftUpdateQuery, function(error2, results2, fields2){
                        if (error2){
                            return connection.rollback(function(){
                                connection.release();
                                next(error2);
                            });
                        }

                        var rgtUpdateQuery = squel.update({seperator:"\n"})
                                                  .table('categories')
                                                  .set('rgt = rgt + 2')
                                                  .where('rgt > ?', (results[0].rgt-1))
                                                  .toString();
                        connection.query(rgtUpdateQuery, function(error3, results3, fields3){
                            if (error3){
                                return connection.rollback(function(){
                                    connection.release();
                                    next(error3);
                                });
                            }

                            var insertQuery = squel.insert({seperator:"\n"})
                                                   .into('categories')
                                                   .set('vendor_id', req.vendor_id)
                                                   .set('parent_id', newCategory.parent_id)
                                                   .set('category_name', newCategory.category_name)
                                                   .set('lft', results[0].rgt)
                                                   .set('rgt', results[0].rgt + 1)
                                                   .toString();
                            connection.query(insertQuery, function(error4, results4, fields4){
                                if (error4){
                                    return connection.rollback(function() {
                                        connection.release();
                                        next(error);
                                    });
                                }
                        
                                connection.commit(function(error){
                                    if (error){
                                        return connection.rollback(function() {
                                            connection.release();
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
            });
        }
    });
});

// [from v1] Vendor: delete category
router.delete('/api/vendor/delete_category', verifyVendorToken, function(req, res, next){
    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var queryString = squel.select({seperator:"\n"})
                                   .from('categories')
                                   .field('lft')
                                   .field('rgt')
                                   .where('category_id = ?', req.body.category_id)
                                   .toString();
            connection.query(queryString, function(error, results, fields){
                if (error){
                    connection.release();
                    next(error);
                } else{
                    console.log(results[0]);
                    var diff = results[0].rgt - results[0].lft;
                    if (diff == 1){
                        connection.beginTransaction(function(error){
                            if (error){
                                connection.release();
                                next(error);
                            }

                            var deleteString = squel.delete({seperator:"\n"})
                                                    .from('categories')
                                                    .where('category_id =?', req.body.category_id)
                                                    .toString();
                            connection.query(deleteString, function(error2, results2, fields2){
                                if (error2){
                                    return connection.rollback(function() {
                                        connection.release();
                                        next(error);
                                    });
                                }

                                var lftUpdateString = squel.update({seperator:"\n"})
                                                        .table('categories')
                                                        .set('lft = lft - 2')
                                                        .where('lft > ?', results[0].rgt)
                                                        .toString();
                                connection.query(lftUpdateString, function(error3, results3, fields3){
                                    if (error3){
                                        return connection.rollback(function(){
                                            connection.release();
                                            next(error);
                                        });
                                    }

                                    var rgtUpdateString = squel.update({seperator:"\n"})
                                                               .table('categories')
                                                               .set('rgt = rgt - 2')
                                                               .where('rgt > ?', results[0].rgt)
                                                               .toString();
                                    connection.query(rgtUpdateString, function(error4, results4, fields4){
                                        if (error4){
                                            return connection.rollback(function(){
                                                connection.release();
                                                next(error);
                                            });
                                        }

                                        connection.commit(function(error){
                                            if (error){
                                                return connection.rollback(function() {
                                                    connection.release();
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
                    } else{
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


// Vendor: Add new product
router.post('/api/vendor/add_product', verifyVendorToken, function(req, res, next){
    /*
    {
        "product_name":
        "category_id":
        "vendor_id":
        "stock":
        "price_original":
        "price_discounted": (optional)
        "tag": (optional)
        "product description": (optional)
    }
    */
    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var newProduct = req.body;
            var queryString = squel.insert({separator:"\n"})
                                   .into('products')
                                   .set('product_name', newProduct.product_name)
                                   .set('category_id', newProduct.category_id)
                                   .set('vendor_id', req.vendor_id)
                                   .set('stock', newProduct.stock)
                                   .set('price_original', newProduct.price_original)
                                   .set('price_discounted', newProduct.price_discounted)
                                   .set('tag', newProduct.tag)
                                   .set('product_description', newProduct.product_description)
                                   .toString();
            connection.query(queryString, function(error, results, fields){
                connection.release();
                if(error){
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
});


// Vendor: Add new products
router.post('/api/vendor/add_products', verifyVendorToken, function(req, res, next){

    /*
    {
        "products" : [
        {"product_name":
        "category_id":
        "vendor_id":
        "stock":
        "price_original":
        "price_discounted": (optional)
        "tag": (optional)
        "product description": (optional)},
        {"product_name":
        "category_id":
        "vendor_id":
        "stock":
        "price_original":
        "price_discounted": (optional)
        "tag": (optional)
        "product description": (optional)},
        .
        .
        .
        ]
    }
    */

    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var newProducts = req.body.products;
            console.log(newProducts);
            var queryString = squel.insert({separator:"\n"})
                                    .into('products')
                                    .setFieldsRows(newProducts)
                                    .toString();
            connection.query(queryString, function(error, results, fields){
                connection.release();
                if(error){
                    next(error);
                }else{
                    res.status(200).json({
                        message: "성공적으로 새 상품들을 등록하였습니다.",
                        results,
                        fields
                    });
                    
                }
            });
        }
    });
});


router.get('/all_products', function(req, res, next){
    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        }
        else{
            var queryString = squel.select({separator:"\n"})
                                   .from('products')
                                   .toString();
            connection.query(queryString, function(error, results, fields){
                if(error){
                    connection.release();
                    next(error);
                }else{
                    connection.release();
                    res.status(200).json({
                        message: "성공적으로 모든 상품들을 가져왔습니다.",
                        results,
                        fields
                    });
                    
                }
            });
        }
    });
});



router.use(function(error, req, res, next){   
    
    next(error);
    
});


// skeleton from zikigo
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
            }
            else{
                req.username = decoded["username"];
                req.customer_id = decoded["customer_id"];
                req.customer_first_name = decoded["customer_first_name"];
                next();
            }
        }); 
    }else{
            res.status(403).json({
            auth:false, 
            token:null
        });
    }
};


function verifyVendorToken(req, res, next){
    var bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined'){
        var bearer = bearerHeader.split(" ");
        var bearerToken = bearer[1];
        jwt.verify(bearerToken, process.env.VENDOR_SECRET_KEY, function(error, decoded) {
            if(error){
                res.status(403).json({
                    auth: false,
                    token: null
                });
            }
            else{
                req.vendor_username = decoded["vendor_username"];
                req.vendor_id = decoded["vendor_id"];
                req.vendor_name = decoded["vendor_name"];
                next();
            }
        });
    }else{
        res.status(403).json({
            auth: false,
            token: null
        });
    }
};


// numberToMoney(60000) returns "6만원" 
// numberToMoney(60000007000) returns "600억7000원"
function numberToMoney(number) {
    var str = (+number).toString().trim();

    if(str.length <= 4){
        return str + '원';
    }else if(str.length <= 8){
        first_four = (+str.substr(-4)); // unary + removes preceding 0's
        if(first_four == '0'){
            first_four = '';
        }
        str = str.slice(0, -4);
        return str + '만' + first_four + '원';
    }else if(str.length <= 12){
        first_four = (+str.substr(-4));
        if(first_four == '0'){
            first_four = '';
        }
        str = str.slice(0, -4);
        second_four = (+str.substr(-4)) + '만';
        if(second_four == '0만'){
            second_four = '';
        }
        str = str.slice(0, -4);
        return str + '억' + second_four + first_four + '원';
    }else{
        throw new error("The number of digits cannot exceed 12. Try a smaller number");
    }
}

// from zikigo
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


module.exports = router;