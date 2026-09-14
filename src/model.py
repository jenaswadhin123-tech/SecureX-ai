"""Model training module for AI vs. Human voice classification.

Builds and trains a scikit-learn classification pipeline with standardization
and a Random Forest Classifier.
"""

from typing import Tuple
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


def create_pipeline(random_state: int = 42) -> Pipeline:
    """Create a standardized classification pipeline.

    Returns
    -------
    Pipeline
        Pipeline with StandardScaler and RandomForestClassifier.
    """
    return Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=100,
                    max_depth=8,
                    min_samples_split=2,
                    class_weight="balanced",
                    random_state=random_state,
                ),
            ),
        ]
    )


def train_model(
    features: np.ndarray, labels: np.ndarray, random_state: int = 42
) -> Tuple[Pipeline, float]:
    """Train and evaluate the voice classification model.

    Parameters
    ----------
    features : np.ndarray
        Feature matrix of shape (n_samples, n_features).
    labels : np.ndarray
        Array of integer labels (0 = Human, 1 = AI).
    random_state : int, optional
        Random seed for reproducibility, defaults to 42.

    Returns
    -------
    Tuple[Pipeline, float]
        (trained_pipeline, validation_accuracy)

    Raises
    ------
    ValueError
        If dataset is empty or lacks samples from both classes.
    """
    if len(features) == 0 or len(labels) == 0:
        raise ValueError("Dataset is empty. Cannot train model.")

    unique_classes, counts = np.unique(labels, return_counts=True)
    if len(unique_classes) < 2:
        raise ValueError(
            f"Dataset must contain samples from both Human and AI classes. "
            f"Found classes: {unique_classes.tolist()}."
        )

    min_class_count = int(np.min(counts))

    # Evaluate validation score based on dataset size
    pipeline = create_pipeline(random_state=random_state)

    if min_class_count >= 3 and len(labels) >= 6:
        # Cross-validation for robust validation estimate
        n_splits = min(5, min_class_count)
        cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
        scores = cross_val_score(pipeline, features, labels, cv=cv, scoring="accuracy")
        validation_accuracy = float(np.mean(scores))
    elif min_class_count >= 2:
        # Train-test split
        X_train, X_val, y_train, y_val = train_test_split(
            features, labels, test_size=0.3, stratify=labels, random_state=random_state
        )
        test_pipeline = create_pipeline(random_state=random_state)
        test_pipeline.fit(X_train, y_train)
        validation_accuracy = float(test_pipeline.score(X_val, y_val))
    else:
        # Very small dataset fallback
        test_pipeline = create_pipeline(random_state=random_state)
        test_pipeline.fit(features, labels)
        validation_accuracy = float(test_pipeline.score(features, labels))

    # Fit pipeline on full dataset for final deployment
    pipeline.fit(features, labels)

    return pipeline, validation_accuracy
