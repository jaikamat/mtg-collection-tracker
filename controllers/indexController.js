const homepage = (req, res, next) => {
    return res.json({
        message: 'This is the home page'
    })
}

const protected = (req, res, next) => {
    return res.json({
        message: 'This is a protected route'
    })
}

module.exports.homepage = homepage;
module.exports.protected = protected;