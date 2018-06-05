//TODO Connection handling while server fatal error required
require('dotenv/config');
const express = require('express');
const app = express();
const morgan = require('morgan');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet')
const cors = require('cors');
const versionOne = require(path.join(__dirname, '/routes/version1'));
const versionTwo = require(path.join(__dirname, '/routes/version2'));




app.use(cors());
app.use(helmet());
app.use(helmet.noCache());
var compression = require('compression');
app.use(compression());
app.use(morgan('dev'));
app.use(bodyParser.urlencoded({
    extended  : false,
}));
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(cookieParser());
app.use('/v1', versionOne);
app.use('/v2', versionTwo);

app.use(function(err,req,res,next){
	if (err){
		next(err);
	}
	else{
		var error = new Error('Not found');
		error.status = 404;
		next(error);
	}
});

app.use(function(error,req,res,next){
    res.status(error.status || 500);
    res.json({
        error:{
			message: error.message,
			stack: error.stack,
        }
    });
});

module.exports = app;