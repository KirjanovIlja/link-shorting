const { Router } = require('express')
const User = require('../models/User')
const router = Router()
const bcrypt = require('bcryptjs')
const { check, validationResult } = require('express-validator')
const jwt = require('jsonwebtoken')
const config = require('config')

router.post(
    '/register',
    [
        check('email', 'Please enter correct email adress.').isEmail(),
        check('password', 'Please enter correct password. At least 8 symbols.').isLength({ min: 8 })
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req)
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: 'Not correct data during registration.'
                })
            }
            const { email, password } = req.body
            const candidate = await User.findOne({ email })

            if (candidate) {
                return res.status(400).json({ message: 'This email address is already in use.' })
            }
            const hashedPassword = await bcrypt.hash(password, 12)
            const user = new User({ email, password: hashedPassword })
            await user.save()

            res.status(201).json({ message: 'User is created' })

        } catch (e) {
            res.status(500).json({ message: 'Something went wrong... Try again!' })
        }
    })

router.post(
    '/login',
    [
        check('email', 'Enter correct email').normalizeEmail().isEmail(),
        check('password', 'Enter a password').exists()
    ],
    async (req, res) => {
        try {
            // Data Validation
            const errors = validationResult(req)
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: 'Not correct data during entering.'
                })
            }

            const { email, password } = req.body
            const user = await User.findOne({ email })
            if (!user) {
                return res.status(400).json({ message: 'User is not found' })
            }
            const isMatch = await bcrypt.compare(password, user.password)

            if (!isMatch) {
                return res.status(400).json({ message: 'Password is not correct. Try again.' })
            }

            const token = jwt.sign(
                { userId: user.id },
                config.get('jwtSecret'),
                { expiresIn: '1h' }
            )

            res.json({ token, userId: user.id })


        } catch (e) {
            res.status(500).json({ message: 'Something went wrong... Try again!' })
        }
    })


module.exports = router