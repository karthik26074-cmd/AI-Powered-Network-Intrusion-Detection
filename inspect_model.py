import joblib

model = joblib.load('nids_model.pkl')

try:
    print("Classes:")
    print(model.classes_)
except Exception as e:
    print(f"Could not get classes: {e}")

try:
    if hasattr(model, 'feature_names_in_'):
        features = model.feature_names_in_
        print("\nFeature Names:")
        for f in features:
            print(f)
    else:
        # Check sub-estimators since VotingClassifier might not have feature_names_in_
        for name, clf in model.named_estimators_.items():
            if hasattr(clf, 'feature_names_in_'):
                print(f"\nFeature Names from {name}:")
                for f in clf.feature_names_in_:
                    print(f)
                break
            else:
                print(f"Estimator {name} has no feature_names_in_")
                try:
                    print(clf.feature_names_)
                except:
                    pass
except Exception as e:
    print(f"Could not get feature names: {e}")
