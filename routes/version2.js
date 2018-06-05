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
const multerS3 = require('multerS3');

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
router.post('/upload', upload.array('photos', 3), function(req, res, next) {
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
        pool.getConnection(function(err, connection){
            if(err){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }
                res.status(500).json({
                    error: err.message,
                    stack: err.stack
                });
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
                        res.status(500).json({
                            status : "Query to the database has failed.",
                            error_message: error.message,
                            error_stack: error.stack
                        });
                    } 
                    else{
                        if (!!results[0]){
                            var password_stored = results[0].password;
                            var passwordIsValid = bcrypt.compareSync(req.body.password, password_stored);
                            if (passwordIsValid){
                                jwt.sign({username: req.body.username, customer_id: results[0].customer_id, customer_first_name: results[0].customer_first_name}, process.env.USER_SECRET_KEY, {expiresIn: '7d'}, function(error, token){
                                    if (error){
                                        res.status(500).json({
                                            status: "Internal Server Error:Token Assignment Denied"
                                        });
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
        "email":
        "phone":
        "address_line1":
        "address_line2": (optional)
        "city":
        "postal_code":
        "country":
    }
    */
    if(!req.body.username || !req.body.password || !req.body.customer_last_name || !req.body.customer_first_name ||
        !req.body.email || !req.body.phone || !req.body.address_line1 || !req.body.city ||
        !req.body.postal_code || !req.body.country){
        res.status(401).json({
            error_message: "REQUIRED FIELDS : (username, password, customer_last_name, customer_first_name, email, phone, address_line1, city, postal_code, country)",
            user_error_message: "필수 항목을 모두 입력하십시오."
        });
    }else if(req.body.username.length < 4 || req.body.username.length > 20 || req.body.password.length < 4 || req.body.password.length > 20 ||
                req.body.phone.length > 20 || req.body.email.length > 30){
        res.status(401).json({
            error_type: "Data Integrity Violation",
            error_message: "입력하신 파라미터 글자 숫자를 참고하세요: username(4~20), password(4~20), phone(~20), email(~30)"
        });
    }
    else{
        pool.getConnection(function(err, connection){
            if(err){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }
                res.status(500).json({
                    error: err.message
                });
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
                                       .set('email', req.body.email)
                                       .set('phone', req.body.phone)
                                       .set('address_line1', req.body.address_line1)
                                       .set('address_line2', req.body.address_line2)
                                       .set('city', req.body.city)
                                       .set('postal_code', req.body.postal_code)
                                       .set('country', req.body.country)
                                       .toString();
                connection.query(queryString, function(error, results, fields){
                    connection.release();
                    if (error){
                        res.status(500).json({
                            code : "QUERY_ERROR POST /api/register customer",
                            auth: false,
                            token: null,
                            error_message: error.message,
                            stack: error.stack
                        });     
                    }
                    else{
                        jwt.sign({username: req.body.username, customer_id: results.customer_id, customer_first_name: req.body.customer_first_name}, process.env.USER_SECRET_KEY, {expiresIn: '7d'}, function(error, token){
                            if (error){
                                res.status(500).json({
                                    code: "JWT_SIGN_ERROR POST /api/register 커스토머 사인",
                                    auth: false,
                                    token: null
                                });
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
    if (!req.body.vendor_username || !req.body.password){
        res.status(401).json({
            error_message: "REQUIRED FIELDS : (username, password)",
            user_error_message: "필수 항목을 모두 입력하십시오."
        });
    }
    else if(req.body.vendor_username.length > 20 || req.body.vendor_username.length < 4 || req.body.password.length > 20 ||  req.body.password.length < 4){
        res.status(401).json({
            error_type: "Data Integrity Violation",
            error_message: "입력하신 파라미터 글자 숫자를 참고하세요: vendor_username(4~20), password(4~20)"
        });
    }
    else{
        pool.getConnection(function(err, connection){
            if(err){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }
                res.status(500).json({
                    error: err.message,
                    stack: err.stack
                });
            }
            else{
                var queryString = squel.select({separator: "\n"})
                                    .from('vendors')
                                    .field('vendor_id')
                                    .field('password')
                                    .field('vendor_name')
                                    .where('vendor_username = ?', req.body.vendor_username)
                                    .toString();
                connection.query(queryString, function(error, results, fields){
                    connection.release();
                    if (error){
                        res.status(500).json({
                            status : "Query to the database has failed.",
                            error_message: error.message,
                            error_stack: error.stack
                        });
                    } 
                    else{
                        if (!!results[0]){
                            console.log(results[0]);
                            console.log(password_stored);
                            var password_stored = results[0].password;
                            var passwordIsValid = bcrypt.compareSync(req.body.password, password_stored);
                            if (passwordIsValid){
                                jwt.sign({vendor_username: req.body.vendor_username, vendor_id: results[0].vendor_id, vendor_name: results[0].vendor_name}, process.env.VENDOR_SECRET_KEY, {expiresIn: '7d'}, function(error, token){
                                    if (error){
                                        res.status(500).json({
                                            status: "Internal Server Error:Token Assignment Denied"
                                        });
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
router.post('/api/vendor/register', function(req, res){
    /*
    {
        "vendor_username":
        "password":
        "vendor_name":
        "email":
        "phone":
        "address_line1":
        "address_line2": (optional)
        "city":
        "postal_code":
        "country":
    }
    */
    if(!req.body.vendor_username || !req.body.password ||  !req.body.vendor_name ||
        !req.body.email || !req.body.phone || !req.body.address_line1 || !req.body.city ||
        !req.body.postal_code || !req.body.country){
        res.status(401).json({
            error_message: "REQUIRED FIELDS : (vendor_username, password, vendor_name, email, phone, address_line1, city, postal_code, country)",
            user_error_message: "필수 항목을 모두 입력하십시오."
        });
    }else if(req.body.vendor_username.length < 4 || req.body.vendor_username.length > 20 || req.body.password.length < 4 || req.body.password.length > 20 ||
                req.body.phone.length > 20 || req.body.email.length > 30){
        res.status(401).json({
            error_type: "Data Integrity Violation",
            error_message: "입력하신 파라미터 글자 숫자를 참고하세요: vendor_username(4~20), password(4~20), phone(~20), email(~30)"
        });
    }
    else{
        pool.getConnection(function(err, connection){
            if(err){
                if(typeof connection !== 'undefined'){
                    connection.release();
                }
                res.status(500).json({
                    error: err.message
                });
            }
            else{
                var hashedPassword = bcrypt.hashSync(req.body.password, parseInt(process.env.SALT_ROUNDS));
                // var clean_phone_number = req.body.phone_number.replace(/-/g,'');
                var queryString = squel.insert({separator: "\n"})
                                       .into('vendors')
                                       .set('vendor_username', req.body.vendor_username)
                                       .set('password', hashedPassword)
                                       .set('vendor_name', req.body.vendor_name)
                                       .set('email', req.body.email)
                                       .set('phone', req.body.phone)
                                       .set('address_line1', req.body.address_line1)
                                       .set('address_line2', req.body.address_line2)
                                       .set('city', req.body.city)
                                       .set('postal_code', req.body.postal_code)
                                       .set('country', req.body.country)
                                       .toString();
                connection.query(queryString, function(error, results, fields){
                    connection.release();
                    if (error){
                        res.status(500).json({
                            code : "QUERY_ERROR POST /api/vendor/register",
                            auth: false,
                            token: null,
                            error_message: error.message,
                            stack: error.stack
                        });     
                    }
                    else{
                        jwt.sign({vendor_username: req.body.vendorusername, vendor_id: results.vendor_id, vendor_name: req.body.vendor_name}, process.env.VENDOR_SECRET_KEY, {expiresIn: '7d'}, function(error, token){
                            if (error){
                                res.status(500).json({
                                    code: "JWT_SIGN_ERROR POST /api/register 벤더 사인",
                                    auth: false,
                                    token: null
                                });
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

router.get('/all_products', function(req, res, next){
    pool.getConnection(function(err, connection){
        if(err){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            res.status(500).json({
                error: err.message
            });
        }
        else{
            var queryString = squel.select({separator:"\n"})
                                   .from('products')
                                   .toString();
            connection.query(queryString, function(error, results, fields){
                if(error){
                    connection.release();
                    res.status(500).json({
                        message: error.message,
                        stack: error.stack
                    });
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


router.put('/api/vendor/add_category', verifyVendorToken, function(req, res, next){
    pool.getConnection(function(err, connection){
        if(err){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            res.status(500).json({
                error: err.message
            });
        }
        else{
            var queryString = squel.insert({separator:"\n"})
                                   .into('categories')
                                   .set('category_name', req.body.category_name)
                                   .toString();
            connection.query(queryString, function(error, results, fields){
                if(error){
                    connection.release();
                    res.status(500).json({
                        message: error.message,
                        stack: error.stack
                    });
                }else{
                    connection.release();
                    res.status(200).json({
                        message: "성공적으로 해당 카테고리를 추가했습니다",
                        results,
                        fields
                    });
                    
                }
            });
        }
    });
});



router.use(function(err, req, res, next){   
    
    next(err);
    
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
        throw new Error("The number of digits cannot exceed 12. Try a smaller number");
    }
}


module.exports = router;