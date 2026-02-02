const mongoose = require('mongoose');
require('../models/User');

mongoose.connect(process.env.MONGODB_URI).then(async () => {
  const User = mongoose.model('User');
  const users = await User.find({}).lean();
  
  console.log('=== ALL USERS IN DATABASE ===');
  console.log('Total users:', users.length);
  
  users.forEach(u => {
    console.log('---');
    console.log('UID:', u.uid);
    console.log('Email:', u.email);
    console.log('Profile:', JSON.stringify(u.state?.profile || {}));
    console.log('Tasks:', (u.state?.tasks || []).length);
    console.log('Subjects:', (u.state?.subjects || []).length);
    if (u.state?.tasks?.length > 0) {
      console.log('Task titles:', u.state.tasks.map(t => t.title).join(', '));
    }
  });
  
  process.exit(0);
}).catch(e => {
  console.error('Error:', e);
  process.exit(1);
});
