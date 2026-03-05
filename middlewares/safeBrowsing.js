const axios = require('axios');

const SAFE_BROWSING_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

module.exports = async (req, res, next) =>{
    const { redirectURL } = req.body;

    const payload = {
        client: { clientId: 'shortify', clientVersion: '1.0' },
        threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: redirectURL }],
        },
    };

    try{
        const response = await axios.post(
            `${SAFE_BROWSING_URL}?key=${process.env.GOOGLE_SAFE_BROWSING_KEY}`,
            payload
        );

        if(response.data && response.data.matches && response.data.matches.length > 0){
            req.flash('error', 'This URL has been flagged as unsafe and cannot be shortened.');
            return res.redirect(req.headers.referer || '/');
        }

        next();
    }
    catch(err){
        console.error('Safe Browsing API error:', err.message);
        next();
    }
};