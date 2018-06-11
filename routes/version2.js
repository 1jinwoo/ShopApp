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


// customer login
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


// customer registration
router.post('/api/register', function(req, res){
    /*
    {
        "username":
        "password":
        "customer_last_name":
        "customer_first_name":
        "customer_email":
        "customer_phone":
        "customer_address_line1":
        "customer_address_line2": (optional)
        "customer_city":
        "customer_postal_code":
        "customer_citycountry":
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


// customer change password
router.put('/api/change_password', verifyToken, function(req, res, next){
    /*
    {
        "password": (current password)
        "new_password":
        "new_password_confirm":
    }
    */
    if(!req.body.password){
        res.status(401).json({
            error_message: "REQUIRED FIELD omitted",
            user_error_message: "비밀번호를 입력해주십시오."
        });
    }

    if(!req.body.new_password || !new_password_confirm){
        res.status(401).json({
            error_message: "REQUIRED FIELDS: (new_password, new_password_confirm) ",
            user_error_message: "새로운 비밀번호와 비밀번호 확인을 입력해주십시오."
        });
    }
    if(req.body.new_password.length < 4 || req.body.new_password.length > 20){
        res.status(401).json({
            error_type: "Date Integrity Violation",
            error_message: "비밀번호는 4자리 이상 20자리 이하로 설정해주세요."
        });
    }

    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var queryString = squel.select({seperator:"\n"})
                                   .from('customers')
                                   .field('password')
                                   .where('username = ?', req.username)
                                   .where('customer_id = ?', req.customer_id)
                                   .toString();
            connection.query(queryString, function(error, results, fields){
                if (error){
                    connection.release();
                    next(error);
                } else{
                    var isValid = bcrypt.compareSync(req.body.password, results[0].password);
                    if (isValid){
                        if (req.body.new_password !== req.body.new_password_confirm){
                            connection.release();
                            res.status(401).json({
                                status: "새로운 비밀번호와 비밀번호 확인이 일치하지 않습니다.",

                            });
                        } else{
                            if (req.body.password === req.body.new_password){
                                connection.release();
                                res.status(401).json({
                                    status: "새로운 비밀번호를 현재 비밀번호와 다르게 설정하세요."
                                });
                            } else{
                                var newPwHashed = bcrypt.hashSync(req.body.new_password, parseInt(process.env.SALT_ROUNDS));
                                var changeQuery = squel.update({seperator:"\n"})
                                                       .table('customers')
                                                       .set('password', newPwHashed)
                                                       .where('username = ?', req.username)
                                                       .where('customer_id = ?', req.customer_id)
                                                       .toString();
                                connection.query(changeQuery, function(error2, results2, fields2){
                                    connection.release();
                                    if (error2){
                                        next(error2);
                                    } else{
                                        res.status(200).json({
                                            message: "비밀번호가 성공적으로 변경되었습니다"
                                        });
                                    }
                                });
                            }
                        }
                    } else{
                        connection.release();
                        res.status(401).json({
                            message: '입력하신 비밀번호가 일치하지 않습니다'
                        });
                    }
                }
            });
        }
    });
});


// vendor login
router.post('/vendor/login', function(req, res){
    if (!req.body.vendor_username || !req.body.vendor_password){
        res.status(401).json({
            error_message: "REQUIRED FIELDS : (vendor_username, vendor_password)",
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


// vendor registration
router.post('/vendor/register', function(req, res, next){

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


// vendor change password
router.put('/vendor/change_password', verifyVendorToken, function(req, res, next){
    /*
    {
        "vendor_password": (current vendor password)
        "new_password":
        "new_password_confirm"
    }
    */

    if(!req.body.vendor_password){
        res.status(401).json({
            error_message: "REQUIRED FIELD vendor_password not entered",
            user_error_message: "벤더 비밀번호가 입력되지 않았습니다."
        });
    }
    if(!req.body.new_password || !req.body.new_password_confirm){
        res.status(401).json({
            error_message: "REQUIRED FIELDS: (new_password, new_password_confirm)",
            user_error_message: "새로운 비밀번호와 비밀번호확인을 입력해주십시오."
        });
    }
    if(req.body.new_password.length < 4 || req.body.new_password.length > 20){
        res.status(401).json({
            error_type: "Date Integrity Violation",
            error_message: "비밀번호는 4자리 이상 20자리 이하로 설정해주세요."
        });
    }

    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var queryString = squel.select({seperator:"\n"})
                                   .from('vendors')
                                   .field('vendor_password')
                                   .where('vendor_id = ?', req.vendor_id)
                                   .toString();
            connection.query(queryString, function(error, results, fields){
                if (error){
                    connection.release();
                    res.status(500).json({
                        message: error.message,
                        stack: error.stack
                    });
                } else{
                    var isValid = bcrypt.compareSync(req.body.vendor_password, results[0].vendor_password);
                    if (isValid){
                        if (req.body.new_password !== req.body.new_password_confirm){
                            connection.release();
                            res.status(401).json({
                                status: "새로운 비밀번호와 비밀번호확인이 일치하지 않습니다.",

                            });
                        } else{
                            if (req.body.vendor_password === req.body.new_password){
                                connection.release();
                                res.status(401).json({
                                    status: "새로운 비밀번호를 현재 비밀번호와 다르게 설정하세요."
                                });
                            } else{
                                var newPwHashed = bcrypt.hashSync(req.body.new_password, 10);
                                var changeQuery = squel.update({seperator:"\n"})
                                                       .table('vendors')
                                                       .set('vendor_password', newPwHashed)
                                                       .where('vendor_id = ?', req.vendor_id)
                                                       .toString();
                                connection.query(changeQuery, function(error2, results2, fields2){
                                    connection.release();
                                    if (error2){
                                        next(error2);
                                    } else{
                                        res.status(200).json({
                                            message: "비밀번호가 성공적으로 변경되었습니다."
                                        });
                                    }
                                });
                            }
                        }
                    } else{
                        connection.release();
                        res.status(401).json({
                            message: '입력하신 비밀번호가 일치하지 않습니다.'
                        });
                    }
                }
            });
        }
    });
});


// [from v1] Vendor: add new category
router.post('/vendor/add_category', verifyVendorToken, function(req, res, next){
    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var newCategory = req.body;
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
                                        message: "성공적으로 카테고리가 추가되었습니다."
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
router.delete('/vendor/delete_category', verifyVendorToken, function(req, res, next){
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
                                                message: "성공적으로 카테고리가 제거되었습니다."
                                            });
                                        });
                                    })
                                });
                            });
                        });
                    } else{
                        connection.release();
                        res.status(401).json({
                            message: "하위 카테고리를 모두 삭제하셔야 합니다."
                        });
                    }
                }
            });
        }
    });
});


// Vendor: Add new product
router.post('/vendor/add_product', verifyVendorToken, function(req, res, next){
    /*
    {
        "product_name":
        "category_id":
        "vendor_id":
        "stock_quantity":
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
                                   .set('stock_quantity', newProduct.stock_quantity)
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
router.post('/vendor/add_products', verifyVendorToken, function(req, res, next){

    /*
    {
        "products" : [
        {"product_name":
        "category_id":
        "vendor_id":
        "stock_quantity":
        "price_original":
        "price_discounted": (optional)
        "tag": (optional)
        "product description": (optional)},
        {"product_name":
        "category_id":
        "vendor_id":
        "stock_quantity":
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


// Vendor: upload product images
router.post('/vendor/upload_images', verifyVendorToken, upload.array('photo', 3), function(req, res, next) {
    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var photosArray = [];
            for (i = 0; i < req.files.length; i++){
                photosArray.push({product_id: req.body.product_id,
                                  image_pathname: req.files[i].key});
            }
            var uploadString = squel.insert({seperator:"\n"})
                                    .into('product_images')
                                    .setFieldsRows(photosArray)
                                    .toString();
            connection.query(uploadString, function(error, results, fields){
                connection.release();
                if (error){
                    next(error);
                } else{
                    res.status(200).json({
                        message: "이미지가 성공적으로 추가되었습니다."
                    });
                }
            });
        }
    });
});


// get products by vendor_id
router.get('/api/get_products_by_vendor_id/:vendor_id', function(req, res, next){
    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else {
            connection.beginTransaction(function(error){
                if(error){
                    connection.rollback(function(){
                        connection.release();
                        next(error);
                    });
                } else {
                    var updateString = squel.update({separator:"\n"})
                                            .table('products')
                                            .set('view_count = view_count + 1')
                                            .where('vendor_id = ?', req.params.vendor_id)
                                            .toString();
                    connection.query(updateString, function(error, results, fields){
                        if(error){
                            connection.rollback(function(){
                                connection.release();
                                next(error);
                            });
                        } else {
                            var queryString = squel.select({sepearator:"\n"})
                                                    .from('products')
                                                    .where('vendor_id = ?', req.params.vendor_id)
                                                    .toString();
                            connection.query(queryString, function(error, results, fields){
                                if(error){
                                    connection.rollback(function(){
                                        connection.release();
                                        next(error);
                                    });
                                } else {
                                    connection.commit(function(error){
                                        if(error){
                                            connection.rollback(function(error){
                                                connection.release();
                                                next(error);
                                            });
                                        } else {
                                            connection.release();
                                            res.status(200).json({
                                                message: "성공적으로 해당 판매자의 상품들을 가져왔습니다.",
                                                results,
                                                fields
                                            });
                                        }
                                    });
                                }
                            });
                        }
                    });
                }
            });
        }
    });
});


// get products by category_id
router.get('/api/get_products_by_category_id/:category_id', function(req, res, next){
    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else {
            connection.beginTransaction(function(error){
                if(error){
                    connection.rollback(function(){
                        connection.release();
                        next(error);
                    });
                } else {
                    var updateString = squel.update({separator:"\n"})
                                            .table('products')
                                            .set('view_count = view_count + 1')
                                            .where('category_id = ?', req.params.category_id)
                                            .toString();
                    connection.query(updateString, function(error, results, fields){
                        if(error){
                            connection.rollback(function(){
                                connection.release();
                                next(error);
                            });
                        } else {
                            var queryString = squel.select({sepearator:"\n"})
                                                    .from('products')
                                                    .where('category_id = ?', req.params.category_id)
                                                    .toString();
                            connection.query(queryString, function(error, results, fields){
                                if(error){
                                    connection.rollback(function(){
                                        connection.release();
                                        next(error);
                                    });
                                } else {
                                    connection.commit(function(error){
                                        if(error){
                                            connection.rollback(function(error){
                                                connection.release();
                                                next(error);
                                            });
                                        } else {
                                            connection.release();
                                            res.status(200).json({
                                                message: "성공적으로 해당 카테고리의 상품들을 가져왔습니다.",
                                                results,
                                                fields
                                            });
                                        }
                                    });
                                }
                            });
                        }
                    });
                }
            });
        }
    });
});


// get all products (does not increment view counts)
router.get('/api/all_products', function(req, res, next){
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

// customer places an order
router.post('/api/order_products', verifyToken, function(req, res, next){
    /*
    {
        "product_id":
        "order_quantity":
        "comments": (optional) 
        "order_address_line1":
        "order_address_line2": (optional)
        "order_city":
        "order_postal_code":
        "order_country":
        "order_phone":
        "order_email":
    }
    */
    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var checkString = squel.select({seperator:"\n"})
                                   .from('products')
                                   .field('stock_quantity')
                                   .field('price_original')
                                   .field('price_discounted')
                                   .field('vendor_id')
                                   .where('product_id = ?', req.body.product_id)
                                   .toString();
            connection.query(checkString, function(error, results, fields){
                if (error){
                    connection.release();
                    next(error);
                } else{
                    if (results[0].stock_quantity < req.body.order_quantity){
                        connection.release();
                        res.status(401).json({
                            message: "상품의 재고가 충분하지 않습니다."
                        });
                    } else{
                        connection.beginTransaction(function(error){
                            if(error){
                                connection.release();
                                next(error);
                            }
                            var newQuantity = results[0].stock_quantity - req.body.order_quantity;
                            var updateString = squel.update({seperator:"\n"})
                                                    .table('products')
                                                    .set('stock_quantity', newQuantity)
                                                    .where('product_id = ?', req.body.product_id)
                                                    .toString();
                            
                            connection.query(updateString, function(error2, results2, fields2){
                                if (error2){
                                    return connection.rollback(function(){
                                        connection.release();
                                        next(error2);
                                    });
                                }

                                var individualPrice;    // checking if there is a discount
                                if (!results[0].price_discounted){
                                    individualPrice = results[0].price_original;
                                } else{
                                    individualPrice = results[0].price_discounted;
                                }

                                var totalPrice = individualPrice * req.body.order_quantity;
                                var insertString = squel.insert({seperator:"\n"})
                                                        .into('orders')
                                                        .set('product_id', req.body.product_id)
                                                        .set('customer_id', req.customer_id)
                                                        .set('vendor_id', results[0].vendor_id)
                                                        .set('order_quantity', req.body.order_quantity)
                                                        .set('price_each', individualPrice)
                                                        .set('price_total', totalPrice)
                                                        .set('order_date', 'NOW()')
                                                        .set('order_status', 'ordered')
                                                        .set('comments', req.body.comments)
                                                        .set('order_address_line1', req.body.order_address_line1)
                                                        .set('order_address_line2', req.body.order_address_line2)
                                                        .set('order_city', req.body.order_city)
                                                        .set('order_country', req.body.order_country)
                                                        .set('order_postal_code', req.body.order_postal_code)
                                                        .set('order_phone', req.body.order_phone)
                                                        .set('order_email', req.body.order_email)
                                                        .toString();
                                connection.query(insertString, function(error3, results3, fields3){
                                    if (error3){
                                        return connection.rollback(function(){
                                            connection.release();
                                            next(error3);
                                        });
                                    }
                                    
                                    var paymentString = squel.insert({seperator:"\n"})
                                                             .into('payments')
                                                             .set('order_id', results3.insertId)
                                                             .set('payment_date', 'NOW()')
                                                             .set('payment_amount', totalPrice)
                                                             .toString();
                                    connection.query(paymentString, function(error4, results4, fields4){
                                        if (error4){
                                            return connection.rollback(function(){
                                                connection.release();
                                                next(error4);
                                            });
                                        }
                                        var incrementString = squel.update({seperator:"\n"})
                                                                    .table('products')
                                                                    .set('order_count = order_count + 1')
                                                                    .where('product_id = ?', req.body.product_id)
                                                                    .toString();
                                        connection.query(incrementString, function(error, results, fields){
                                            if (error){
                                                return connection.rollback(function(){
                                                    connection.release();
                                                    next(error);
                                                });
                                            }
                                        });
                                        connection.commit(function(error){
                                            if (error){
                                                return connection.rollback(function(){
                                                    connection.release();
                                                    next(error);
                                                });
                                            }
                                            connection.release();
                                            res.status(200).json({
                                                message: "주문이 성공적으로 완료되었습니다.",
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

// guest places an order
router.post('/api/order_products/guest', function(req, res, next){
    /*
    {
        "product_id":
        "order_quantity":
        "comments": (optional) 
        "order_address_line1":
        "order_address_line2": (optional)
        "order_city":
        "order_postal_code":
        "order_country":
        "order_phone":
        "order_email":
    }
    */
    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var checkString = squel.select({seperator:"\n"})
                                   .from('products')
                                   .field('stock_quantity')
                                   .field('price_original')
                                   .field('price_discounted')
                                   .field('vendor_id')
                                   .where('product_id = ?', req.body.product_id)
                                   .toString();
            connection.query(checkString, function(error, results, fields){
                if (error){
                    connection.release();
                    next(error);
                } else{
                    if (results[0].stock_quantity < req.body.order_quantity){
                        connection.release();
                        res.status(401).json({
                            message: "상품의 재고가 충분하지 않습니다"
                        });
                    } else{
                        connection.beginTransaction(function(error){
                            if(error){
                                connection.release();
                                next(error);
                            }
                            var newQuantity = results[0].stock_quantity - req.body.order_quantity;
                            var updateString = squel.update({seperator:"\n"})
                                                    .table('products')
                                                    .set('stock_quantity', newQuantity)
                                                    .where('product_id =?', req.body.product_id)
                                                    .toString();
                            
                            connection.query(updateString, function(error2, results2, fields2){
                                if (error2){
                                    return connection.rollback(function(){
                                        connection.release();
                                        next(error2);
                                    });
                                }

                                var individualPrice;
                                if (!results[0].price_discounted){
                                    individualPrice = results[0].price_original;
                                } else{
                                    individualPrice = results[0].price_discounted;
                                }

                                var totalPrice = individualPrice * req.body.order_quantity;
                                var insertString = squel.insert({seperator:"\n"})
                                                        .into('orders')
                                                        .set('product_id', req.body.product_id)
                                                        .set('vendor_id', results[0].vendor_id)
                                                        .set('order_quantity', req.body.order_quantity)
                                                        .set('price_each', individualPrice)
                                                        .set('price_total', totalPrice)
                                                        .set('order_date', 'NOW()')
                                                        .set('order_status', 'ordered')
                                                        .set('order_address_line1', req.body.order_address_line1)
                                                        .set('order_address_line2', req.body.order_address_line2)
                                                        .set('order_city', req.body.order_city)
                                                        .set('order_country', req.body.order_country)
                                                        .set('order_postal_code', req.body.order_postal_code)
                                                        .set('order_phone', req.body.order_phone)
                                                        .set('order_email', req.body.order_email)
                                                        .toString();
                                connection.query(insertString, function(error3, results3, fields3){
                                    if (error3){
                                        return connection.rollback(function(){
                                            connection.release();
                                            next(error3);
                                        });
                                    }
                                    
                                    var paymentString = squel.insert({seperator:"\n"})
                                                             .into('payments')
                                                             .set('order_id', results3.insertId)
                                                             .set('payment_amount', totalPrice)
                                                             .toString();
                                    connection.query(paymentString, function(error4, results4, fields4){
                                        console.log(error4);
                                        if (error4){
                                            return connection.rollback(function(){
                                                connection.release();
                                                next(error3);
                                            });
                                        }
                                        var incrementString = squel.update({seperator:"\n"})
                                                                    .table('products')
                                                                    .set('order_count = order_count + 1')
                                                                    .where('product_id = ?', req.body.product_id)
                                                                    .toString();
                                        connection.query(incrementString, function(error, results, fields){
                                            if (error){
                                                return connection.rollback(function(){
                                                    connection.release();
                                                    next(error);
                                                });
                                            }
                                        });
                                        connection.commit(function(error){
                                            if (error){
                                                return connection.rollback(function(){
                                                    connection.release();
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
                    }
                }
            });
        }
    });
});

// processes a payment (TODO: need to add actual payment transaction)
router.delete('/api/process_payment', function(req, res, next){
    pool.getConnection(function(error, connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        }
        else {
            var queryString = squel.delete({separator: "\n"})
                                    .from(payments)
                                    .where("order_id = ?", req.body.order_id)
                                    .toString();
            connection.query(queryString, function(error, results, fields){
                connection.release();
                if(error){
                    next(error);
                }
                else {
                    res.status(201).json({
                        message: "성공적으로 지불되었습니다.",
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