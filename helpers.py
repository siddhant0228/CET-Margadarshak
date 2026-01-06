import pandas as pd
from app import db, College, Branch, Cutoff, CollegeBranch

def import_cap_data(file_path, round_number):
    df = pd.read_excel(file_path)

    for _, row in df.iterrows():
        college = College.query.filter_by(code=str(row["Institute code"]).strip()).first()
        if not college:
            college = College(code=str(row["Institute code"]).strip(), name=str(row["College"]).strip())
            db.session.add(college)
            db.session.flush()

        branch = Branch.query.filter_by(code=str(row["Branch code"]).strip()).first()
        if not branch:
            branch = Branch(code=str(row["Branch code"]).strip(), name=str(row["Branch name"]).strip())
            db.session.add(branch)
            db.session.flush()

        cutoff = Cutoff(
            round=round_number,
            allocation_type=str(row["Allocation type"]).strip(),
            category=str(row["Category"]).strip(),
            merit_number=row.get("merit number"),
            percentile=row.get("percentile"),
            college=college,
            branch=branch
        )
        db.session.add(cutoff)

    db.session.commit()
    print(f"Imported CAP round {round_number} successfully!")

def import_pivot_gopens(file_path, round_number):
    df = pd.read_excel(file_path)

    for _, row in df.iterrows():
        college = College.query.filter_by(code=str(row["Institute code"]).strip()).first()
        if not college:
            college = College(code=str(row["Institute code"]).strip(), name=str(row["College"]).strip())
            db.session.add(college)
            db.session.flush()

        for branch_name in df.columns[2:]:
            if pd.notna(row[branch_name]):
                branch = Branch.query.filter_by(name=branch_name.strip()).first()
                if not branch:
                    branch = Branch(code=f"B{branch_name[:3].upper()}", name=branch_name.strip())
                    db.session.add(branch)
                    db.session.flush()

                cb = CollegeBranch.query.filter_by(
                    college_id=college.id, branch_id=branch.id, round=round_number
                ).first()

                if not cb:
                    cb = CollegeBranch(college=college, branch=branch, round=round_number)
                    db.session.add(cb)

    db.session.commit()
    print(f"Imported pivot GOPENS round {round_number} successfully!")

if __name__ == "__main__":
    from app import app
    with app.app_context():
        import_cap_data("cap1.xlsx", 1)
        import_cap_data("cap2.xlsx", 2)
        import_cap_data("cap3.xlsx", 3)
        import_pivot_gopens("pivot_gopens_cap1.xlsx", 1)
        import_pivot_gopens("pivot_gopens_cap2.xlsx", 2)
        import_pivot_gopens("pivot_gopens_cap3.xlsx", 3)
