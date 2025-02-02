module.exports = {
    ensureAuthenticated: (req, res, next) => {
        if (req.isAuthenticated()) return next();
        req.flash('error', 'Please log in to view this resource');
        res.redirect('/users/login');
    },
    ensureAdmin: (req, res, next) => {
        if (req.isAuthenticated() && req.user.role === 'admin') return next();
        req.flash('error', 'Unauthorized');
        res.redirect('/dashboard');
    }
};
