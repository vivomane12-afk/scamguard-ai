import streamlit as st
import joblib
import os
import pandas as pd
import matplotlib.pyplot as plt

from risk_engine import analyze_risk


# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="ScamGuard AI",
    page_icon="🛡️",
    layout="wide"
)


# ==========================================
# CUSTOM CSS
# ==========================================

st.markdown("""
<style>

    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1200px;
    }

    .main-title {
        font-size: 3rem;
        font-weight: 700;
        margin-bottom: 0.2rem;
    }

    .subtitle {
        font-size: 1.15rem;
        opacity: 0.75;
        margin-bottom: 1.5rem;
    }

    .section-title {
        font-size: 1.45rem;
        font-weight: 650;
        margin-top: 1rem;
        margin-bottom: 0.8rem;
    }

    .metric-card {
        padding: 18px;
        border-radius: 12px;
        border: 1px solid rgba(128, 128, 128, 0.25);
        text-align: center;
        min-height: 105px;
    }

    .metric-value {
        font-size: 1.65rem;
        font-weight: 700;
    }

    .metric-label {
        font-size: 0.85rem;
        opacity: 0.7;
        margin-top: 5px;
    }

    .dataset-card {
        padding: 16px;
        border-radius: 12px;
        border: 1px solid rgba(128, 128, 128, 0.22);
        text-align: center;
    }

    .dataset-number {
        font-size: 1.5rem;
        font-weight: 700;
    }

    .dataset-label {
        font-size: 0.85rem;
        opacity: 0.7;
    }

    .explanation-box {
        padding: 18px;
        border-radius: 12px;
        border: 1px solid rgba(128, 128, 128, 0.22);
        margin-top: 10px;
    }

    .chart-card {
        padding: 15px;
        border-radius: 12px;
        border: 1px solid rgba(128, 128, 128, 0.20);
        margin-bottom: 15px;
    }

    .footer {
        text-align: center;
        opacity: 0.55;
        font-size: 0.8rem;
        padding-top: 15px;
    }

</style>
""", unsafe_allow_html=True)


# ==========================================
# LOAD MODEL
# ==========================================

@st.cache_resource
def load_model():
    return joblib.load("model/scam_detector.pkl")


model = load_model()


# ==========================================
# SESSION STATE
# ==========================================

if "message" not in st.session_state:
    st.session_state.message = ""


# ==========================================
# QUICK TEST FUNCTIONS
# ==========================================

def use_scam_example():

    st.session_state.message = (
        "Click this link to claim your prize of 5000000"
    )


def use_legitimate_example():

    st.session_state.message = (
        "Hey, are you coming to college today?"
    )


# ==========================================
# HEADER
# ==========================================

st.markdown(
    '<div class="main-title">🛡️ ScamGuard AI</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Explainable AI-Based Phishing and Scam Detection System'
    '</div>',
    unsafe_allow_html=True
)

st.write(
    "Analyze suspicious SMS, messages and emails using "
    "Machine Learning and rule-based risk analysis."
)

st.divider()


# ==========================================
# MESSAGE ANALYSIS
# ==========================================

st.markdown(
    '<div class="section-title">🔍 Analyze a Message</div>',
    unsafe_allow_html=True
)

message = st.text_area(
    "Enter a suspicious message:",
    key="message",
    height=150,
    placeholder=(
        "Example: Congratulations! "
        "You won ₹5000000. Click here to claim..."
    ),
    label_visibility="visible"
)


# ==========================================
# QUICK TEST BUTTONS
# ==========================================

col1, col2, col3 = st.columns([1.2, 1.5, 5])

with col1:

    st.button(
        "🔴 Scam Example",
        on_click=use_scam_example
    )

with col2:

    st.button(
        "🟢 Legitimate Example",
        on_click=use_legitimate_example
    )


# ==========================================
# ANALYZE BUTTON
# ==========================================

st.write("")

analyze_clicked = st.button(
    "🔍  Analyze Message",
    type="primary",
    width="stretch"
)


# ==========================================
# ANALYSIS RESULT
# ==========================================

if analyze_clicked:

    if not message.strip():

        st.warning(
            "Please enter a message to analyze."
        )

    else:

        # ==================================
        # ML PREDICTION
        # ==================================

        probabilities = model.predict_proba(
            [message]
        )[0]

        legitimate_probability = probabilities[0]
        scam_probability = probabilities[1]


        # ==================================
        # HYBRID ANALYSIS
        # ==================================

        result = analyze_risk(
            message,
            scam_probability
        )

        final_score = result["final_score"]
        risk_level = result["risk_level"]
        prediction = result["prediction"]
        indicators = result["indicators"]


        st.divider()


        # ==================================
        # MAIN RESULT
        # ==================================

        if prediction == "SCAM / PHISHING":

            st.error(
                "🚨  SCAM / PHISHING DETECTED"
            )

        else:

            st.success(
                "✅  MESSAGE APPEARS LEGITIMATE"
            )


        # ==================================
        # RISK LEVEL + SCORE
        # ==================================

        col1, col2 = st.columns(2)

        with col1:

            st.markdown(
                f"### Risk Level: **{risk_level}**"
            )

        with col2:

            st.markdown(
                f"### Final Risk Score: **{final_score:.2f}%**"
            )


        st.progress(
            min(int(final_score), 100)
        )


        # ==================================
        # PREDICTION DETAILS
        # ==================================

        st.markdown(
            '<div class="section-title">📊 Prediction Details</div>',
            unsafe_allow_html=True
        )

        col1, col2, col3 = st.columns(3)

        with col1:

            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-value">
                        {scam_probability * 100:.2f}%
                    </div>
                    <div class="metric-label">
                        ML Scam Probability
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with col2:

            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-value">
                        {legitimate_probability * 100:.2f}%
                    </div>
                    <div class="metric-label">
                        ML Legitimate Probability
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with col3:

            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-value">
                        {result["rule_score"]:.2f}%
                    </div>
                    <div class="metric-label">
                        Rule-Based Score
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )


        # ==================================
        # DETECTED INDICATORS
        # ==================================

        st.markdown(
            '<div class="section-title">🚩 Detected Indicators</div>',
            unsafe_allow_html=True
        )

        if indicators:

            for indicator in indicators:

                st.write(
                    "✓  " + indicator
                )

        else:

            st.write(
                "No major suspicious indicators detected."
            )


        # ==================================
        # EXPLANATION
        # ==================================

        st.markdown(
            '<div class="section-title">💡 Why was this result given?</div>',
            unsafe_allow_html=True
        )

        if prediction == "SCAM / PHISHING":

            st.markdown(
                '<div class="explanation-box">',
                unsafe_allow_html=True
            )

            st.write(
                "The system identified suspicious "
                "characteristics in the message."
            )

            if indicators:

                for indicator in indicators:

                    st.write(
                        "• " + indicator
                    )

            st.write(
                f"ML scam probability: "
                f"{scam_probability * 100:.2f}%"
            )

            st.write(
                f"Rule-based score: "
                f"{result['rule_score']:.2f}%"
            )

            st.write(
                f"Final hybrid risk score: "
                f"{final_score:.2f}%"
            )

            st.markdown(
                '</div>',
                unsafe_allow_html=True
            )

        else:

            st.markdown(
                '<div class="explanation-box">',
                unsafe_allow_html=True
            )

            st.write(
                f"The ML model estimated a scam probability "
                f"of {scam_probability * 100:.2f}%."
            )

            st.write(
                "No major suspicious rule-based indicators "
                "were detected."
            )

            st.write(
                f"Final hybrid risk score: "
                f"{final_score:.2f}%"
            )

            st.markdown(
                '</div>',
                unsafe_allow_html=True
            )


        # ==================================
        # SAFETY RECOMMENDATION
        # ==================================

        st.markdown(
            '<div class="section-title">🛡️ Safety Recommendation</div>',
            unsafe_allow_html=True
        )

        if risk_level == "CRITICAL":

            st.error(
                "Do not click links, send money, share OTPs "
                "or provide personal information. "
                "Verify the sender through an official source."
            )

        elif risk_level == "HIGH":

            st.warning(
                "Be very careful with this message. "
                "Do not click suspicious links or provide "
                "financial or personal information."
            )

        elif risk_level == "MEDIUM":

            st.warning(
                "The message contains some suspicious "
                "characteristics. Verify the sender before "
                "taking any action."
            )

        else:

            st.info(
                "No major scam indicators were detected. "
                "However, always verify unexpected messages."
            )


# ==========================================
# MODEL & DATASET ANALYSIS
# ==========================================

st.divider()

st.markdown(
    '<div class="section-title">📊 Model & Dataset Analysis</div>',
    unsafe_allow_html=True
)

st.caption(
    "Performance of the TF-IDF + Logistic Regression "
    "classifier on the held-out test dataset."
)


# ==========================================
# MODEL METRICS
# ==========================================

st.markdown("#### 🎯 Model Performance")

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.markdown(
        """
        <div class="metric-card">
            <div class="metric-value">96.14%</div>
            <div class="metric-label">Accuracy</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col2:

    st.markdown(
        """
        <div class="metric-card">
            <div class="metric-value">100.00%</div>
            <div class="metric-label">Precision</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col3:

    st.markdown(
        """
        <div class="metric-card">
            <div class="metric-value">71.14%</div>
            <div class="metric-label">Recall</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col4:

    st.markdown(
        """
        <div class="metric-card">
            <div class="metric-value">83.14%</div>
            <div class="metric-label">F1-Score</div>
        </div>
        """,
        unsafe_allow_html=True
    )


# ==========================================
# DATASET OVERVIEW
# ==========================================

st.markdown("#### 📚 Dataset Overview")

col1, col2, col3 = st.columns(3)

with col1:

    st.markdown(
        """
        <div class="dataset-card">
            <div class="dataset-number">5,572</div>
            <div class="dataset-label">Total Messages</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col2:

    st.markdown(
        """
        <div class="dataset-card">
            <div class="dataset-number">4,825</div>
            <div class="dataset-label">Legitimate Messages</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col3:

    st.markdown(
        """
        <div class="dataset-card">
            <div class="dataset-number">747</div>
            <div class="dataset-label">Scam / Spam Messages</div>
        </div>
        """,
        unsafe_allow_html=True
    )


# ==========================================
# VISUAL ANALYSIS
# ==========================================

st.markdown("#### 📈 Visual Analysis")

col1, col2 = st.columns(2)


# ==========================================
# DATASET DISTRIBUTION
# ==========================================

with col1:

    st.markdown(
        '<div class="chart-card">',
        unsafe_allow_html=True
    )

    st.markdown("##### Message Distribution")

    distribution = pd.DataFrame({
        "Type": ["Legitimate", "Scam / Spam"],
        "Messages": [4825, 747]
    })

    fig, ax = plt.subplots(figsize=(5, 3.2))

    ax.bar(
        distribution["Type"],
        distribution["Messages"]
    )

    ax.set_ylabel("Number of Messages")
    ax.set_ylim(0, 5200)

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    for i, value in enumerate(distribution["Messages"]):

        ax.text(
            i,
            value + 100,
            f"{value:,}",
            ha="center",
            fontsize=10
        )

    plt.tight_layout()

    st.pyplot(
        fig,
        use_container_width=True
    )

    plt.close(fig)

    st.markdown(
        '</div>',
        unsafe_allow_html=True
    )


# ==========================================
# CONFUSION MATRIX
# ==========================================

with col2:

    st.markdown(
        '<div class="chart-card">',
        unsafe_allow_html=True
    )

    st.markdown("##### Confusion Matrix")

    if os.path.exists(
        "model/confusion_matrix.png"
    ):

        st.image(
            "model/confusion_matrix.png",
            width="stretch"
        )

    else:

        st.info(
            "Confusion matrix image not found."
        )

    st.markdown(
        '</div>',
        unsafe_allow_html=True
    )


# ==========================================
# MODEL PERFORMANCE
# ==========================================

st.markdown(
    '<div class="chart-card">',
    unsafe_allow_html=True
)

st.markdown("##### Model Performance Comparison")

performance = pd.DataFrame({
    "Metric": [
        "Accuracy",
        "Precision",
        "Recall",
        "F1-Score"
    ],
    "Score": [
        96.14,
        100.00,
        71.14,
        83.14
    ]
})

fig, ax = plt.subplots(figsize=(9, 3.5))

ax.barh(
    performance["Metric"],
    performance["Score"]
)

ax.set_xlim(0, 105)
ax.set_xlabel("Score (%)")

ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)

for i, value in enumerate(performance["Score"]):

    ax.text(
        value + 1,
        i,
        f"{value:.2f}%",
        va="center",
        fontsize=10
    )

plt.tight_layout()

st.pyplot(
    fig,
    use_container_width=True
)

plt.close(fig)

st.markdown(
    '</div>',
    unsafe_allow_html=True
)

# ==========================================
# FOOTER
# ==========================================

st.divider()

st.warning(
    "⚠️ Educational Purpose Only: ScamGuard AI is developed "
    "as a college academic project for educational and "
    "demonstration purposes. The results are AI-based "
    "predictions and should not be considered a guarantee "
    "that a message is safe or malicious."
)

st.markdown(
    """
    <div class="footer">
        🛡️ ScamGuard AI • Explainable AI-Based Scam Detection System
    </div>
    """,
    unsafe_allow_html=True
)