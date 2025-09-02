const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const auth = require('../middleware/authMiddleware');

const router = express.Router();

// Register route
router.post('/register', async (req, res) => {
  try {
    const { name , email, password } = req.body;
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: "User already exists" });
    const hashPass = await bcrypt.hash(password, 10);

    user = new User({name ,email,password : hashPass});
    await user.save();

    res.json({ msg: 'User Successfully registered' });
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
});

// Login route
router.post('/login',async(req,res) => {
  try{
    const {email ,password} = req.body;
    const user = await User.findOne({email});
    if(!user) return res.status(400).json({msg : 'Userdoen not exists'});

    const isMatch = await bcrypt.compare(password , user.password);
    if(!isMatch) return res.status(400).json({msg : 'Invalid Credentails'});

    const token = jwt.sign({id : user._id}, process.env.JWT_SECRET, {expiresIn : '1h'});
    res.json({token , user :{id : user._id , name : user.name , email : user.email}});
  }catch(err){
    res.status(500).json({ error: err.message });
  }
})

// Update route
router.put('/update', auth, async (req, res) => {
  try {
    const { name } = req.body;
    const user = await User.findByIdAndUpdate(req.user.id, { name }, { new: true });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete route
router.delete('/delete', auth, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.user.id);
    res.json({ msg: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
