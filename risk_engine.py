import re


def analyze_risk(message, ml_probability):

    text = message.lower()

    indicators = []
    rule_score = 0

    # ==========================================
    # 1. LOTTERY / WINNING
    # ==========================================

    lottery_words = [
        "lottery",
        "lotto",
        "jackpot",
        "lucky draw",
        "lucky winner"
    ]

    winning_words = [
    "you won",
    "you win",
    "you have won",
    "you have win",
    "you've won",
    "you've win",
    "winner",
    "won",
    "win",
    "winning",
    "congratulations"
    ]

    if any(word in text for word in lottery_words):
        indicators.append("Lottery / lucky draw language")
        rule_score += 30

    if any(word in text for word in winning_words):
        indicators.append("Unexpected winning language")
        rule_score += 20


    # ==========================================
    # 2. LARGE MONEY AMOUNT
    # ==========================================

    # IMPORTANT:
    # Only treat a number as money when it has:
    # currency symbol OR money-related wording.

    money_context = [
    "₹",
    "rs",
    "inr",
    "rupees",
    "rupee",
    "dollar",
    "dollars",
    "usd",
    "pounds",
    "euro",
    "money",
    "cash",
    "prize",
    "reward",
    "won",
    "win",
    "winning",
    "amount"
    ]
    has_money_context = any(
        word in text for word in money_context
    )

    large_amount_found = False

    if has_money_context:

        # Find numbers
        amounts = re.findall(
            r'\d[\d,]*',
            text
        )

        for amount in amounts:

            try:

                number = int(
                    amount.replace(",", "")
                )

                # Ignore likely OTP values
                # when explicitly described as OTP
                if (
                    "otp" in text
                    and 4 <= len(amount.replace(",", "")) <= 8
                ):
                    continue

                if number >= 100000:

                    large_amount_found = True
                    break

            except ValueError:
                pass


    if large_amount_found:

        indicators.append(
            "Large monetary amount"
        )

        rule_score += 30


    # ==========================================
    # 3. PRIZE / REWARD
    # ==========================================

    prize_words = [
        "prize",
        "reward",
        "cash prize",
        "cash reward",
        "free money",
        "gift voucher"
    ]

    if any(word in text for word in prize_words):

        indicators.append(
            "Prize / reward language"
        )

        rule_score += 15


    # ==========================================
    # 4. URGENCY
    # ==========================================

    urgency_words = [
        "urgent",
        "immediately",
        "hurry",
        "act now",
        "call now",
        "last chance",
        "within 24 hours",
        "expires today",
        "verify now"
    ]
   
    if any(word in text for word in urgency_words):

        indicators.append(
            "Urgent or pressure language"
        )

        rule_score += 15


    # ==========================================
    # 5. BANK / ACCOUNT SECURITY
    # ==========================================

    security_words = [
        "bank account",
        "account blocked",
        "account suspended",
        "verify your account",
        "verify account",
        "password",
        "login",
        "credit card",
        "debit card"
    ]

    if any(word in text for word in security_words):

        indicators.append(
            "Account / financial security language"
        )

        rule_score += 20


    # ==========================================
    # 6. LINK DETECTION
    # ==========================================

    link_phrases = [
    "click this link",
    "click the link",
    "click here",
    "tap this link",
    "tap the link",
    "open this link",
    "visit this link",
    "follow this link"
    ]

    actual_link = re.search(
        r'https?://|www\.|bit\.ly|tinyurl|\.com/|\.in/',
        text
    )

    if actual_link or any(
        phrase in text for phrase in link_phrases
    ):  

        indicators.append(
            "Suspicious link detected"
        )

        rule_score += 20

    # ==========================================
    # 7. OTP / PERSONAL INFORMATION
    # ==========================================

    if any(word in text for word in [
        "share your otp",
        "send otp",
        "tell me your otp"
    ]):

        indicators.append(
            "Request for sensitive OTP information"
        )

        rule_score += 35

    elif any(word in text for word in [
        "otp",
        "pin",
        "cvv",
        "verification code"
    ]):

        indicators.append(
            "OTP / verification language"
        )

        rule_score += 5


    # ==========================================
    # 8. PHONE NUMBER
    # ==========================================

    # Only detect a phone number when it looks
    # like an actual phone number.
    #
    # This avoids treating huge money amounts
    # such as 4000000000 as phone numbers.

    phone_pattern = r'(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)'

    if re.search(phone_pattern, text):

        indicators.append(
            "Phone number detected"
        )

        rule_score += 5


    # ==========================================
    # 9. LIMIT RULE SCORE
    # ==========================================

    rule_score = min(rule_score, 100)


    # ==========================================
    # 10. COMBINE ML + RULE SCORE
    # ==========================================

    ml_score = ml_probability * 100

    final_score = (
        (ml_score * 0.50) +
        (rule_score * 0.50)
    )


    # ==========================================
    # 11. STRONG SCAM OVERRIDES
    # ==========================================

    # Lottery + large amount
    if (
        any(word in text for word in lottery_words)
        and large_amount_found
    ):

        final_score = max(
            final_score,
            90
        )


    # Winning + large amount
    if (
        any(word in text for word in winning_words)
        and large_amount_found
    ):

        final_score = max(
            final_score,
            85
        )


    # Bank/account + urgency
    if (
        any(word in text for word in [
            "bank account",
            "account blocked",
            "verify your account"
        ])
        and
        any(word in text for word in [
            "urgent",
            "immediately",
            "verify now",
            "click"
        ])
    ):

        final_score = max(
            final_score,
            80
        )


    # ==========================================
    # 12. LIMIT FINAL SCORE
    # ==========================================

    final_score = min(
        final_score,
        100
    )


    # ==========================================
    # 13. RISK LEVEL
    # ==========================================

    if final_score < 25:

        risk_level = "LOW"

    elif final_score < 50:

        risk_level = "MEDIUM"

    elif final_score < 75:

        risk_level = "HIGH"

    else:

        risk_level = "CRITICAL"


    # ==========================================
    # 14. FINAL PREDICTION
    # ==========================================

    if final_score >= 50:

        prediction = "SCAM / PHISHING"

    else:

        prediction = "LEGITIMATE"


    # ==========================================
    # 15. RETURN RESULT
    # ==========================================

    return {
        "prediction": prediction,
        "risk_level": risk_level,
        "final_score": final_score,
        "ml_score": ml_score,
        "rule_score": rule_score,
        "indicators": indicators
    }
