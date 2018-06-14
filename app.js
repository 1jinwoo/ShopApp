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

app.use(function(err, req,res,next){
	console.error(err);
	next(err);
});

//Route중에 아무것도 없었을때 여기로 와서 404와 메세지 받아서감.
app.use(function(err,req,res,next){
	//error handling 
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
	if(process.env.NODE_ENV == "PRODUCTION"){
		error.stack = null;
	}
	res.status(error.status || 500);
	res.json({
		error: error
	});    
});

module.exports = app;