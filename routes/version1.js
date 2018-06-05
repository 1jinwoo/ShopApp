require('dotenv/config');
const express = require('express');
const router = express.Router();
const pool = require('../db.js');
const squel = require('squel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');


/*
router.use(function(req,res,next){
    if(process.env.NODE_ENV =='DEVELOPMENT'){
        console.log(req.body);
    }
    
    next();
})
*/


// Customer: register new customer data using hash function
router.post('/api/register', function(req, res, next){
    pool.getConnection(function(err,connection){
		if(err){
			if(typeof connection !== 'undefined'){
				connection.release();
			}
			res.status(500).json({
				error: err.message
			});
		}
		else{
            var newUser = req.body;
            bcrypt.hash(newUser.password, 10, function(err, hash) {
                if(err) {
                    connection.release();
                    next(err);
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
                                   .set('customer_address1', newUser.address1)
                                   .set('customer_address2', newUser.address2)
                                   .set('customer_city', newUser.city)
                                   .set('customer_postalcode', newUser.postalcode)
                                   .set('customer_country', newUser.country)
                                   .set('customer_email', newUser.email)
                                   .toString();
                    connection.query(registerQuery, function(error, results, fields){
                        if(error){
                            connection.release();
                            res.status(500).json({
						        message: error.message,
						        stack: error.stack
					        });
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
                                    res.status(500).json({
                                        message: error2.message,
                                        stack: error2.stack
                                    });
                                } else{
                                    if (!!results2) {
                                        jwt.sign({username: results2[0].username, user_id: results.insertId,
                                        full_name: results2[0].customer_name, vendor_id: results2[0].vendor_id},
                                        process.env.USER_SECRET_KEY, {expiresIn: '7d'}, 
                                        function(error, token){
                                            if (error){
                                                res.status(500).json({
                                                    status: "Token Assignment Failed",
                                                    message: error.message
                                                });
                                            } else{
                                                res.status(200).json({
                                                    message: "회원가입이 완료되었습니다",
                                                    auth: true,
                                                    token: token
                                                });
                                            }
                                        });
                                    } else{
                                        res.status(401).json({
                                            message: "Internal Server Error: Registration Failed"
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
});

// Customer: verify user upon login request using hash function, provides token if success
router.post('/api/login', function(req, res, next){
    pool.getConnection(function(err,connection){
		if(err){
			if(typeof connection !== 'undefined'){
				connection.release();
			}
			res.status(500).json({
				error: err.message
			});
		}
		else{
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
                    res.status(500).json({
                        status: "Query to the database has failed",
                        results,
                        message: error.message,
                        stack: error.stack
                    });
                } else{
                    if (!!results[0]){
                        var isValid = bcrypt.compareSync(loginUser.password, results[0].password);
                        if (isValid){
                            jwt.sign({username: loginUser.username, user_id: results[0].id,
                            full_name: results[0].customer_name, vendor_id: results[0].vendor_id},
                            process.env.USER_SECRET_KEY, {expiresIn: '7d'}, 
                            function(error, token){
                                if (error){
                                    res.status(500).json({
                                        status: "Token Assignment Failed"
                                    });
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

// Customer: change password once login-ed
router.put('/api/register', verifyToken, function(req, res, next){
    pool.getConnection(function(err, connection){
		if(err){
			if(typeof connection !== 'undefined'){
				connection.release();
			}
			res.status(500).json({
				error: err.message
			});
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
                                                       .table('customers')
                                                       .set('password', newPwHashed)
                                                       .where('username = ?', req.username)
                                                       .where('vendor_id = ?', req.vendor_id)
                                                       .toString();
                                connection.query(changeQuery, function(error2, results2, fields2){
                                    connection.release();
                                    if (error2){
                                        res.status(500).json({
                                            status: 'Internal database error',
                                            error: error2.message,
                                            stack: error2.stack
                                        });
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


// Vendor: register new vendor data using hash function
router.post('/vendor/register', function(req, res, next){
    pool.getConnection(function(err,connection){
		if(err){
			if(typeof connection !== 'undefined'){
				connection.release();
			}
			res.status(500).json({
				error: err.message
			});
		}
		else{
            var newVendor = req.body;
            bcrypt.hash(newVendor.password, 10, function(err, pwHash) {
                if(err) {
                    connection.relase();
                    next(err);
                } else {
                    var registerQuery = squel.insert({separator:"\n"})
                                   .into('vendors')
                                   .set('vendor_username', newVendor.username)
                                   .set('vendor_password', pwHash)
                                   .set('vendor_name', newVendor.name)
                                   .set('vendor_email', newVendor.email)
                                   .set('vendor_phone', newVendor.phone)
                                   .set('vendor_address1', newVendor.address1)
                                   .set('vendor_address2', newVendor.address2)
                                   .set('vendor_city', newVendor.city)
                                   .set('vendor_country', newVendor.country)
                                   .set('vendor_postalcode', newVendor.postalcode)
                                   .toString();
                    connection.query(registerQuery, function(error, results, fields){
                        if(error){
                            connection.release();
                            res.status(500).json({
						        message: error.message,
						        stack: error.stack
					        });
                        }else{
                            var requestQuery = squel.select({seperator:"\n"})
                                                    .field('vendor_username')
                                                    .field('vendor_name')
                                                    .from('vendors')
                                                    .where('vendor_id =?', results.insertId)
                                                    .toString();
                            connection.query(requestQuery, function(error2, results2, fields2){ 
                                connection.release();
                                if (error2){
                                    res.status(500).json({
                                        message: error2.message,
                                        stack: error2.stack
                                    });
                                } else{
                                   
                                    if (!!results2) {
                                        jwt.sign({vendor_username: results2[0].vendor_username, 
                                        vendor_id: results.insertId, vendor_name: results2[0].vendor_name},
                                        process.env.USER_SECRET_KEY, {expiresIn: '7d'}, 
                                        function(error, token){
                                            if (error){
                                                res.status(500).json({
                                                    status: "Token Assignment Failed",
                                                    message: error.message
                                                });
                                            } else{
                                                res.status(200).json({
                                                    message: "회원가입이 완료되었습니다",
                                                    auth: true,
                                                    token: token
                                                });
                                            }
                                        });
                                    } else{
                                        res.status(401).json({
                                            message: "Internal Server Error: Registration Failed"
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
});

// Vendor: verify user upon login request using hash function, provides token if success
router.post('/vendor/login', function(req, res, next){
    pool.getConnection(function(err,connection){
		if(err){
			if(typeof connection !== 'undefined'){
				connection.release();
			}
			res.status(500).json({
				error: err.message
			});
		}
		else{
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
                    res.status(500).json({
                        status: "Query to the database has failed",
                        results,
                        message: error.message,
                        stack: error.stack
                    });
                } else{
                    if (!!results[0]){
                        var isValid = bcrypt.compareSync(loginVendor.password, results[0].password);
                        if (isValid){
                            jwt.sign({vendor_username: loginVendor.username, vendor_id: results[0].id,
                            vendor_name: results[0].name},
                            process.env.USER_SECRET_KEY, {expiresIn: '7d'}, 
                            function(error, token){
                                if (error){
                                    res.status(500).json({
                                        status: "Token Assignment Failed"
                                    });
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

// Vendor: change password once login-ed
router.put('/vendor/register', verifyVendorToken, function(req, res, next){
    pool.getConnection(function(err, connection){
		if(err){
			if(typeof connection !== 'undefined'){
				connection.release();
			}
			res.status(500).json({
				error: err.message
			});
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
                                        res.status(500).json({
                                            status: 'Internal database error',
                                            error: error2.message,
                                            stack: error2.stack
                                        });
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


// List all products information upon request
router.get('/all_products', function(req, res, next){
    pool.getConnection(function(err,connection){
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

// Add new product
router.post('/vendor/add_product', verifyVendorToken, function(req, res, next){
    pool.getConnection(function(err,connection){
		if(err){
			if(typeof connection !== 'undefined'){
				connection.release();
			}
			res.status(500).json({
				error: err.message
			});
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
            connection.query(queryString, function(error, results, fields){
                connection.release();
                if(error){
                    res.status(500).json({
						message: error.message,
						stack: error.stack
					});
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

// Add new category1 (biggest)
router.post('/vendor/add_category1', verifyVendorToken, function(req, res, next){
    pool.getConnection(function(err,connection){
		if(err){
			if(typeof connection !== 'undefined'){
				connection.release();
			}
			res.status(500).json({
				error: err.message
			});
		}
		else{
            var newCategory = req.body;
            var queryString = squel.insert({separator:"\n"})
                                   .into('categories1')
                                   .set('category1_name', newCategory.name)
                                   .set('vendor_id', req.vendor_id)
                                   .toString();
            connection.query(queryString, function(error, results, fields){
                connection.release();
                if(error){
                    res.status(500).json({
						message: error.message,
						stack: error.stack
					});
                }else{
                    res.status(200).json({
                        message: "성공적으로 새 카테고리를 등록하였습니다.",
                        results,
                        fields
                    });
                    
                }
            });
        }
    });
});

// Add new category2 (middle)
router.post('/vendor/add_category2', verifyVendorToken, function(req, res, next){
    pool.getConnection(function(err,connection){
		if(err){
			if(typeof connection !== 'undefined'){
				connection.release();
			}
			res.status(500).json({
				error: err.message
			});
		}
		else{
            var newCategory = req.body;
            var queryString = squel.insert({separator:"\n"})
                                   .into('categories2')
                                   .set('category2_name', newCategory.name)
                                   .set('vendor_id', req.vendor_id)
                                   .set('category1_id', newCategory.category1_id)
                                   .toString();
            connection.query(queryString, function(error, results, fields){
                connection.release();
                if(error){
                    res.status(500).json({
						message: error.message,
						stack: error.stack
					});
                }else{
                    res.status(200).json({
                        message: "성공적으로 새 카테고리를 등록하였습니다.",
                        results,
                        fields
                    });
                    
                }
            });
        }
    });
});

// Add new category3 (smallest)
router.post('/vendor/add_category3', verifyVendorToken, function(req, res, next){
    pool.getConnection(function(err,connection){
		if(err){
			if(typeof connection !== 'undefined'){
				connection.release();
			}
			res.status(500).json({
				error: err.message
			});
		}
		else{
            var newCategory = req.body;
            var queryString = squel.insert({separator:"\n"})
                                   .into('categories3')
                                   .set('category3_name', newCategory.name)
                                   .set('category2_id', newCategory.category2_id)
                                   .set('vendor_id', req.vendor_id)
                                   .toString();
            connection.query(queryString, function(error, results, fields){
                connection.release();
                if(error){
                    res.status(500).json({
						message: error.message,
						stack: error.stack
					});
                }else{
                    res.status(200).json({
                        message: "성공적으로 새 카테고리를 등록하였습니다.",
                        results,
                        fields
                    });
                    
                }
            });
        }
    });
});

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
	}else{
		res.status(403).json({
			auth:false, 
			token:null
		});
	}
};

router.use(function(err, req, res, next){	
	
	next(err);
	
});


module.exports = router;