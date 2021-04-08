const express = require('express');
const multer = require('multer');
const sharp = require('sharp');

const User = require('./../models/user');
const auth = require('./../middleware/auth');

const router = new express.Router();
const upload = multer({
    limits: {
        fieldSize: 1000000 // 1MB
    },
    fileFilter(req, file, cb) {
        if(!file.originalname.match(/\.(jpg|jpeg|png)$/)) {
            cb(new Error('Please upload an image!'))
        }
        cb(undefined, true);
    }
});

router.post('/users', async (req, res) => {
    const user = new User(req.body);
    try {
        await user.save();
        const token = await user.generateAuthToken();
        res.status(201).send({user, token});
    } catch (error) {
        res.status(400).send();   
    }
});

router.post('/users/login', async (req, res) => {
    try {
        const user = await User.findByCredentials(req.body.email, req.body.password);
        const token = await user.generateAuthToken();
        res.status(200).send({user, token});
    } catch (error) {
        res.status(400).send();
    }
});

router.post('/users/logout', auth, async (req, res) => {
    try {
        req.user.tokens = req.user.tokens.filter(token => {
            token.token !== req.token;
        });
        await req.user.save();
        res.status(200).send();
    } catch (error) {
        res.status(500).send();
    }
});

router.post('/users/logoutAll', auth, async (req, res) => {
    try {
        req.user.tokens = [];
        await req.user.save();
        res.status(200).send();
    } catch (error) {
        res.status(500).send();
    }
});

router.get('/users/me', auth, async (req, res) => {
    res.status(200).send(req.user);
});

router.patch('/users/me', auth, async (req, res) => {
    const updates = Object.keys(req.body);
    const allowedUpdates = ['name', 'email', 'password', 'age'];
    const isValidOperation = updates.every(update => {
        return allowedUpdates.includes(update);
    });
    if(!isValidOperation){
        return res.status(400).send({error: 'Invalid update!'})
    }
    try {
        updates.forEach(update => {
            req.user[update] = req.body[update]; 
        });
        await req.user.save();
        res.status(200).send(req.user);
    } catch (error) {
        res.status(400).send(error);
    }
});

router.delete('/users/me', auth, async (req, res) => {
    try {
        await req.user.remove();
        res.status(202).send(req.user);
    } catch (error) {
        res.status(500).send();
    }
});

router.post('/users/me/avatar', auth, upload.single('avatar'), async (req, res) => {
    const buffer = await sharp(req.file.buffer).resize({width: 250, height: 250}).png().toBuffer();
    req.user.avatar = buffer;
    await req.user.save();
    res.status(200).send();
}, (err, req, res, next) => {
    res.status(400).send({error: err.message});
});

router.delete('/users/me/avatar', auth, async (req, res) => {
    try {
        req.user.avatar = undefined;
        await req.user.save();
        res.status(202).send()
    } catch (error) {
        res.status(500).send();
    }
});

router.get('/users/:id/avatar', async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if(!user || !user.avatar) {
            throw new Error();
        }
        res.set('Content-Type', 'image/png');
        res.status(200).send(user.avatar);
    } catch (error) {
        res.status(404).send();
    }
});

module.exports = router;