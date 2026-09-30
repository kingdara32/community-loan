// Fill these in before going live. They appear in the app footer and in every contract.
module.exports = {
  LENDER_NAME: process.env.LENDER_NAME || '[Lender legal name]',
  SEC_NO: process.env.SEC_NO || '[SEC registration / Certificate of Authority no.]',
  SUPPORT_URL: process.env.SUPPORT_URL || '', // live chat link (WhatsApp, Messenger, Telegram)
  SUPPORT_HOURS: '09:00 - 21:00',
  RATE: Number(process.env.RATE || 0.3), // % per MONTH, flat. Set with your lawyer.
  MIN_AMOUNT: 80000,
  MAX_AMOUNT: 5000000,
  TERMS: [6, 12, 24, 36, 48],
};
