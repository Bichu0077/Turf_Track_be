import Razorpay from 'razorpay';

const razorpayKeyId = process.env.RAZORPAY_KEY_ID;
const razorpayKeySecret = process.env.RAZORPAY_KEY_SECRET;

let razorpay = null;
if (razorpayKeyId && razorpayKeySecret) {
  razorpay = new Razorpay({
    key_id: razorpayKeyId,
    key_secret: razorpayKeySecret,
  });
  console.log('Razorpay initialized successfully');
} else {
  console.warn('Razorpay configuration missing. Payment features will be disabled.');
}

export { razorpay, razorpayKeyId, razorpayKeySecret };
