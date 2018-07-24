import peewee
from datetime import datetime
from playhouse.postgres_ext import ArrayField


database = peewee.PostgresqlDatabase(
    database="updater_db",
    user="admin",
    password="123",
    host="localhost",
    port="5432"
)

class VULNERABILITIES(peewee.Model):
    class Meta:
        database = database
        ordering = ("componentversion_string", )
        table_name = "vulnerabilities"

    id = peewee.PrimaryKeyField(
        null=False)
    vulnerability_id = peewee.TextField(
        default="",
        unique=True,
        verbose_name="CVE ID")
    componentversion = ArrayField(
        peewee.TextField,
        default=[],
        verbose_name="componentversion",
        index=False)
    cwe = ArrayField(
        peewee.TextField,
        default=[],
        verbose_name="CWE",
        index=False)
    capec = ArrayField(
        peewee.TextField,
        default=[],
        verbose_name='capec',
        index=False)
    references = ArrayField(
        peewee.TextField,
        default=[],
        verbose_name="References",
        index=False)
    vulnerable_configuration = ArrayField(
        peewee.TextField,
        default=[],
        verbose_name="Vulnerable Configuration (CPE strings)",
        index=False)
    data_type = peewee.TextField(
        default="",
        verbose_name="Data Type")
    data_version = peewee.TextField(
        default="",
        verbose_name="Data Version")
    data_format = peewee.TextField(
        default="",
        verbose_name="Data Format")
    description = peewee.TextField(
        default="",
        verbose_name="Description")
    published = peewee.DateTimeField(
        default=datetime.now,
        verbose_name="Published Date")
    modified = peewee.DateTimeField(
        default=datetime.now,
        verbose_name="Modified Date")
    access = peewee.TextField(
        default='{"vector": "", "complexity": "", "authentication": ""}',
        verbose_name="Access structure")
    impact = peewee.TextField(
        default='{"confidentiality": "", "integrity": "", "availability": ""}',
        verbose_name="Impact Structure")
    vector_string = peewee.TextField(
        default="",
        verbose_name="Vector String")
    cvss_time = peewee.DateTimeField(
        default=datetime.now,
        verbose_name="CVSS Time")
    cvss = peewee.FloatField(
        default=0.0,
        verbose_name="CVSS")
    componentversion_string = peewee.TextField(
        default="",
        verbose_name="Component Version array as Text"
    )
    metadata = peewee.TextField(
        default=""
    )

    def __unicode__(self):
        return "vulnerabilities"

    def __str__(self):
        return str(self.vulnerability_id)

    @property
    def to_json(self):
        return dict(
            id=self.id,
            vulnerability_id=self.vulnerability_id,
            componentversion=self.componentversion,
            cwe=self.cwe,
            capec=self.capec,
            references=self.references,
            vulnerable_configuration=self.vulnerable_configuration,
            data_type=self.data_type,
            data_version=self.data_version,
            data_format=self.data_format,
            description=self.description,
            published=self.published,
            modified=self.modified,
            access=self.access,
            impact=self.impact,
            vector_string=self.vector_string,
            cvss_time=self.cvss_time,
            cvss=self.cvss,
            componentversion_string=self.componentversion_string,
            metadata=self.metadata,
        )

    @property
    def to_tuple(self):
        return (
            self.vulnerability_id,
            self.componentversion,
            self.cwe,
            self.capec,
            self.references,
            self.vulnerable_configuration,
            self.data_type,
            self.data_version,
            self.data_format,
            self.description,
            self.published,
            self.modified,
            self.access,
            self.impact,
            self.vector_string,
            self.cvss_time,
            self.cvss,
            self.componentversion_string,
            self.metadata,
        )

def connect_database():
    if database.is_closed:
        database.connect()

def disconnect_database():
    if not database.is_closed:
        database.close()

def count_vulners():
    connect_database()
    count = VULNERABILITIES.select().count()
    disconnect_database()
    return count

def find_vulner_by_id_in_database(id):
    vulners = list(VULNERABILITIES.select().where(VULNERABILITIES.vulnerability_id == id))
    if len(vulners) > 0:
        return vulners[0].to_json
    return None

def update_vulner_by_id_in_database(id, data):
    pass