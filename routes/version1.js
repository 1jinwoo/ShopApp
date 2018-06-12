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
    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var loginUser = req.body;
            var queryString = squel.select({seperator:"\n"})
                                   .field('password')
                                   .field('customer_id', 'id')
                                   .field('customer_fullname', 'customer_name')
                                   .field('vendor_id')
                                   .from('customers')
                                   .where('username =?',loginUser.username )
                                   .toString();
            connection.query(queryString, function(error, results, fields){
                connection.release();
                if(error){
                    next(error);
                } else{
                    if (!!results[0]){
                        var isValid = bcrypt.compareSync(loginUser.password, results[0].password);
                        if (isValid){
                            jwt.sign({username: loginUser.username, user_id: results[0].id,
                            full_name: results[0].customer_name, vendor_id: results[0].vendor_id},
                            process.env.USER_SECRET_KEY, {expiresIn: '7d'}, 
                            function(error, token){
                                if (error){
                                    next(error);
                                } else{
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
});

// Customer: register new customer data using hash function
router.post('/api/register', function(req, res, next){
    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var newUser = req.body;
            bcrypt.hash(newUser.password, 10, function(error, hash) {
                if(error) {
                    connection.release();
                    next(error);
                } else {
                    var pwHash = hash;
                    var registerQuery = squel.insert({separator:"\n"})
                                   .into('customers')
                                   .set('vendor_id', newUser.vendor_id)
                                   .set('username', newUser.username)
                                   .set('password', pwHash)
                                   .set('customer_lastname', newUser.last_name)
                                   .set('customer_firstname', newUser.first_name)
                                   .set('customer_fullname', newUser.last_name+newUser.first_name)
                                   .set('customer_phone', newUser.phone)
                                   .set('customer_address_line1', newUser.address1)
                                   .set('customer_address_line2', newUser.address2)
                                   .set('customer_city', newUser.city)
                                   .set('customer_postal_code', newUser.postalcode)
                                   .set('customer_country', newUser.country)
                                   .set('customer_email', newUser.email)
                                   .toString();
                    connection.query(registerQuery, function(error, results, fields){
                        if(error){
                            connection.release();
                            next(error);
                        }else{
                            var requestQuery = squel.select({seperator:"\n"})
                                                    .field('username')
                                                    .field('customer_fullname', 'customer_name')
                                                    .field('vendor_id')
                                                    .from('customers')
                                                    .where('customer_id =?', results.insertId)
                                                    .toString();
                            connection.query(requestQuery, function(error2, results2, fields2){
                                connection.release();
                                if (error2){
                                    next(error2);
                                } else{
                                    if (!!results2) {
                                        jwt.sign({username: results2[0].username, user_id: results.insertId,
                                        full_name: results2[0].customer_name, vendor_id: results2[0].vendor_id},
                                        process.env.USER_SECRET_KEY, {expiresIn: '7d'}, 
                                        function(error, token){
                                            if (error){
                                                next(error);
                                            } else{
                                                res.status(200).json({
                                                    message: "회원가입이 완료되었습니다",
                                                    auth: true,
                                                    token: token
                                                });
                                            }
                                        });
                                    } else{
                                        next(error);
                                    }
                                }
                            })
                        }
                    });
                }
            });
        }
    });
});

// Customer: change password once login-ed
router.put('/api/register', verifyToken, function(req, res, next){
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
                                   .where('vendor_id = ?', req.vendor_id)
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
                                status: "새로운 비밀번호가 일치하지 않습니다",

                            });
                        } else{
                            if (req.body.password === req.body.new_password){
                                connection.release();
                                res.status(401).json({
                                    status: "새로운 비밀번호를 현재 비밀번호와 다르게 설정하세요"
                                });
                            } else{
                                var newPwHashed = bcrypt.hashSync(req.body.new_password, 10);
                                var changeQuery = squel.update({seperator:"\n"})
                                                       .table('customers')
                                                       .set('password', newPwHashed)
                                                       .where('username = ?', req.username)
                                                       .where('vendor_id = ?', req.vendor_id)
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
 
// Customer: add product to the customer's shopping cart
router.post('/api/add_cart', verifyToken, function(req, res, next){
    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var checkString = squel.select({seperator:"\n"})
                                   .from('carts')
                                   .field('cart_id')
                                   .where('customer_id =?', req.user_id)
                                   .toString();
            connection.query(checkString, function(error, results, fields){
                if (error){
                    connection.release();
                    next(error);
                } else{
                    if(!results.length){
                        connection.beginTransaction(function(error){
                            if (error){
                                connection.release();
                                next(error);
                            }
                            var insertCartString = squel.insert({seperator:"\n"})
                                                        .into('carts')
                                                        .set('customer_id', req.user_id)
                                                        .toString();
                            connection.query(insertCartString, function(error2, results2, fields2){
                                if (error2){
                                    return connection.rollback(function(){
                                        connection.release();
                                        next(error2);
                                    });
                                }
                                var insertPCString = squel.insert({seperator:"\n"})
                                                          .into('products_carts')
                                                          .set('cart_id', results2.insertId)
                                                          .set('product_id', req.body.product_id)
                                                          .set('cart_quantity', req.body.quantity)
                                                          .toString();
                                connection.query(insertPCString, function(error3, results3, fields3){
                                    if (error3){
                                        return connection.rollback(function(){
                                            connection.release();
                                            next(error3);
                                        });
                                    }

                                    connection.commit(function(error){
                                        if (error){
                                            return connection.rollback(function(){
                                                connection.release();
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
                    } else{
                        var checkString2 = squel.select({seperator:"\n"})
                                                .from('products_carts')
                                                .field('cart_quantity')
                                                .where('cart_id =?', results[0].cart_id)
                                                .where('product_id =?', req.body.product_id)
                                                .toString();
                        connection.query(checkString2, function(error2, results2, fields2){
                            if (error2){
                                connection.release();
                                next(error2);
                            } else{
                                var addCartString;
                                if (results2.length){
                                    addCartString = squel.update({seperator:"\n"})
                                                        .table('products_carts')
                                                        .set(`cart_quantity = cart_quantity + ${req.body.quantity}`)
                                                        .where('cart_id =?', results[0].cart_id)
                                                        .where('product_id =?', req.body.product_id)
                                                        .toString();
                                } else{
                                    addCartString = squel.insert({seperator:"\n"})
                                                        .into('products_carts')
                                                        .set('cart_id', results[0].cart_id)
                                                        .set('product_id', req.body.product_id)
                                                        .set('cart_quantity', req.body.quantity)
                                                        .toString();
                                }
                                
                                connection.query(addCartString, function(error3, results3, fields3){
                                    connection.release();
                                    if (error3){
                                        next(error3);
                                    } else{
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

// Customer: order products from the shopping cart
router.post('/api/order_products', verifyToken, function(req, res, next){
    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var productsQuery = squel.select({seperator:"\n"})
                                     .field('pc.product_id')
                                     .field('pc.cart_quantity')
                                     .from('carts', 'c')
                                     .join('products_carts', 'pc', 'pc.cart_id = c.cart_id')
                                     .where('c.cart_id =?', req.body.cart_id)
            var checkString = squel.select({seperator:"\n"})
                                   .field('p.product_id')
                                   .field('p.stock_quantity')
                                   .field('p.price_original')
                                   .field('p.price_discounted')
                                   .field('c.cart_quantity')
                                   .from('products', 'p')
                                   .join(productsQuery, 'c', 'c.product_id = p.product_id')
                                   .toString();
            connection.query(checkString, function(error, results, fields){
                if (error){
                    connection.release();
                    next(error);
                } else{
                    var isNotEnough = 0;
                    for (i = 0; i < results.length; i++) {
                        if (results[i].stock_quantity < results[i].cart_quantity) {
                            isNotEnough = 1;
                        }
                    }
                    if (isNotEnough){
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
                            var clauseString = 'UPDATE products SET stock_quantity = CASE product_id ';
                            var whereString = 'WHERE product_id IN (';
                            var newQuantity;
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
                            
                            connection.query(updateString, function(error2, results2, fields2){
                                if (error2){
                                    return connection.rollback(function(){
                                        connection.release();
                                        next(error2);
                                    });
                                }
                                var totalPrice = 0;
                                var insertArray = [];

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
                                var insertString = squel.insert({seperator:"\n"})
                                                        .into('orders')
                                                        .set('customer_id', req.user_id)
                                                        .set('vendor_id', req.vendor_id)
                                                        .set('price_total', totalPrice)
                                                        .set('order_date', 'NOW()')
                                                        .set('order_status', 'ordered')
                                                        .set('order_address_line1', req.body.address1)
                                                        .set('order_address_line2', req.body.address2)
                                                        .set('order_city', req.body.city)
                                                        .set('order_country', req.body.country)
                                                        .set('order_postal_code', req.body.postalcode)
                                                        .set('order_name', req.body.name)
                                                        .set('order_phone', req.body.phone)
                                                        .set('order_email', req.body.email)
                                                        .toString();
                                connection.query(insertString, function(error3, results3, fields3){
                                    if (error3){
                                        return connection.rollback(function(){
                                            connection.release();
                                            next(error3);
                                        });
                                    }
                                    for (i = 0; i < results.length; i++){
                                        insertArray[i].order_id = results3.insertId;
                                    }

                                    var insertString2 = squel.insert({seperator:"\n"})
                                                             .into('orderdetails')
                                                             .setFieldsRows(insertArray)
                                                             .toString();

                                    connection.query(insertString2, function(error4, results4, fields4){
                                        if (error4){
                                            return connection.rollback(function(){
                                                connection.release();
                                                next(error4);
                                            });
                                        }
                                        var paymentString = squel.insert({seperator:"\n"})
                                                                 .into('payments')
                                                                 .set('order_id', results3.insertId)
                                                                 .set('amount', totalPrice)
                                                                 //.set('payment_method', ?)
                                                                 .toString();
                                        connection.query(paymentString, function(error5, results5, fields5){
                                            if (error5){
                                                return connection.rollback(function(){
                                                    connection.release();
                                                    next(error5);
                                                });
                                            }
                                            
                                            var deleteString = squel.delete({seperator:"\n"})
                                                                   .from('carts')
                                                                   .where('cart_id =?', req.body.cart_id)
                                                                   .toString();
                                            connection.query(deleteString, function(error6, resulst6, fields6){
                                                if (error6){
                                                    return connection.rollback(function(){
                                                        connection.release();
                                                        next(error6);
                                                    });
                                                }
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
                            });
                        });
                    }
                }
            });
        }
    });
});

// Customer: modify customer's shopping cart
router.post('/api/modify_cart', verifyToken, function(req, res, next){
    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        }
        else {
            var modifyString;
            if (req.body.quantity == 0){
                modifyString = squel.delete({seperator:"\n"})
                                    .from('products_carts')
                                    .where('product_id =?', req.body.product_id)
                                    .where('cart_id =?', req.body.cart_id)
                                    .toString();
            } else{
                modifyString = squel.update({seperator:"\n"})
                                    .table('products_carts')
                                    .set('cart_quantity', req.body.quantity)
                                    .where('product_id =?', req.body.product_id)
                                    .where('cart_id =?', req.body.cart_id)
                                    .toString();
            }
            connection.query(modifyString, function(error, results, fields){
                connection.release();
                if (error){
                    next(error);
                } else{
                    res.status(200).json({
                        message: "성공적으로 장바구니가 변경되었습니다"
                    });
                }
            });
        }
    });
})

router.post('/api/order_products/guest', function(req, res, next){
    pool.getConnection(function(error,connection){
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
                                   .where('product_id =?', req.body.product_id)
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
                                                        .set('vendor_id', req.body.vendor_id)
                                                        .set('quantity', req.body.order_quantity)
                                                        .set('price_each', individualPrice)
                                                        .set('price_total', totalPrice)
                                                        .set('order_date', 'NOW()')
                                                        .set('order_status', 'ordered')
                                                        .set('order_address_line1', req.body.address1)
                                                        .set('order_address_line2', req.body.address2)
                                                        .set('order_city', req.body.city)
                                                        .set('order_country', req.body.country)
                                                        .set('order_postal_code', req.body.postalcode)
                                                        .set('order_name', req.body.name)
                                                        .set('order_phone', req.body.phone)
                                                        .set('order_email', req.body.email)
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
                                                             .set('amount', totalPrice)
                                                         //  .set('payment_method', ?)
                                                             .toString();
                                    connection.query(paymentString, function(error4, results4, fields4){
                                        if (error4){
                                            return connection.rollback(function(){
                                                connection.release();
                                                next(error3);
                                            });
                                        }
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

// Vendor: verify user upon login request using hash function, provides token if success
router.post('/vendor/login', function(req, res, next){
    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var loginVendor = req.body;
            var queryString = squel.select({seperator:"\n"})
                                   .field('vendor_password', 'password')
                                   .field('vendor_id', 'id')
                                   .field('vendor_name', 'name')
                                   .from('vendors')
                                   .where('vendor_username =?',loginVendor.username )
                                   .toString();
            connection.query(queryString, function(error, results, fields){
                connection.release();
                if(error){
                    next(error);
                } else{
                    if (!!results[0]){
                        var isValid = bcrypt.compareSync(loginVendor.password, results[0].password);
                        if (isValid){
                            jwt.sign({vendor_username: loginVendor.username, vendor_id: results[0].id,
                            vendor_name: results[0].name},
                            process.env.USER_SECRET_KEY, {expiresIn: '7d'}, 
                            function(error, token){
                                if (error){
                                    next(error);
                                } else{
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
});

// Vendor: register new vendor data using hash function
router.post('/vendor/register', function(req, res, next){
    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            connection.beginTransaction(function(error){
                if (error){
                    connection.release();
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
                                         .set('vendor_postal_code', newVendor.postalcode)
                                         .toString();
                connection.query(registerString, function(error, results, fields){
                    if(error){
                        return connection.rollback(function() {
                            connection.release();
                            next(error);
                        });
                    }

                    var requestString = squel.select({seperator:"\n"})
                                            .field('vendor_username')
                                            .field('vendor_name')
                                            .from('vendors')
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
                                                .field('MAX(rgt)', 'rgt')
                                                .from('categories')
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
                                    process.env.USER_SECRET_KEY, {expiresIn: '7d'}, 
                                    function(error, token){
                                        if (error){
                                            return connection.rollback(function(){
                                                connection.release();
                                                next(error);
                                            });
                                        }
                                        connection.commit(function(error){
                                            if (error){
                                                return connection.rollback(function(){
                                                    connection.release();
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
                                } else{
                                    connection.release();
                                    next(error);
                                }
                            });
                        });
                    });
                });
            });
        }
    });
});

// Vendor: change password once login-ed
router.put('/vendor/register', verifyVendorToken, function(req, res, next){
    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
            var queryString = squel.select({seperator:"\n"})
                                   .from('vendors')
                                   .field('vendor_password', 'password')
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
                    var isValid = bcrypt.compareSync(req.body.password, results[0].password);
                    if (isValid){
                        if (req.body.new_password !== req.body.new_password_confirm){
                            connection.release();
                            res.status(401).json({
                                status: "새로운 비밀번호가 일치하지 않습니다",

                            });
                        } else{
                            if (req.body.password === req.body.new_password){
                                connection.release();
                                res.status(401).json({
                                    status: "새로운 비밀번호를 현재 비밀번호와 다르게 설정하세요"
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

// Vendor: Add new product
router.post('/vendor/add_product', verifyVendorToken, function(req, res, next){
    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
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

// Vendor: add new category
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
                                   .where('vendor_id =?', req.vendor_id)
                                   .toString();
            } else{
                queryString = squel.select({seperator:"\n"})
                                   .from('categories')
                                   .field('lft')
                                   .field('rgt')
                                   .where('category_id =?', newCategory.parent_id)
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
                                        next(error4);
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

// Vendor: delete category
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
                                   .where('category_id =?', req.body.category_id)
                                   .toString();
            connection.query(queryString, function(error, results, fields){
                if (error){
                    connection.release();
                    next(error);
                } else{
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
                                        next(error2);
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
                                            next(error3);
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
                                                next(error4);
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

// Vendor: upload product images
router.post('/vendor/upload_images', verifyVendorToken, upload.array('photo', 3), function(req, res, next) {
    pool.getConnection(function(error,connection){
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
                        message: "이미지가 성공적으로 추가되었습니다"
                    });
                }
            });
        }
    });
});

// List all products information upon request
router.get('/all_products', function(req, res, next){
    pool.getConnection(function(error,connection){
        if(error){
            if(typeof connection !== 'undefined'){
                connection.release();
            }
            next(error);
        } else{
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
                req.user_id = decoded["user_id"];
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
};

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
};

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

router.use(function(error, req, res, next){
	next(error);
});

module.exports = router;