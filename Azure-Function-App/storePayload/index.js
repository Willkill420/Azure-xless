module.exports = async function (context, req) {

    if (req.body) {
        context.log("XSS FOUND - " + JSON.stringify(req.body));
    }
    else {
        context.res = {
            status: 400,
            body: "Please GET or send a valid payload"
        };
    }
};