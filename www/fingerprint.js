var exec = require('cordova/exec');

exports.coolMethod = function (arg0, success, error) {
    exec(success, error, 'fingerprint', 'coolMethod', [arg0]);
};
module.exports.add = function (arg0,success, error)
{
    exec(success , error, 'fingerprint' , 'register' , [arg0]);
}