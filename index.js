require("dotenv").config()
const express = require("express")
const mongoose = require("mongoose")
const cors = require("cors")
const multer = require("multer")
const path = require("path")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3")
const { v4: uuidv4 } = require("uuid")
const app = express()
const PORT = process.env.PORT || 5050

// Middleware  ynk
app.use(express.json())
app.use(cors({
     origin: "https://pfe-teal.vercel.app", // Allow this origin
  methods: ["GET", "POST"], // Specify allowed methods
  credentials: true // Allow credentials if needed
 
}));
app.use(express.urlencoded({ limit: "50mb", extended: true }))

//app.use("/uploads", express.static("uploads"))

// Connexion à MongoDB Atlas
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB Atlas Connected"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err))

// Schéma des offres d'emploi
const offreSchema = new mongoose.Schema({
  titre: String,
  description: String,
  entreprise: { type: String, required: true },
  lieu: String,
  salaire: Number,
  date_publication: Date,
  id_recruteur: String,
  candidatures: [{ type: mongoose.Schema.Types.ObjectId, ref: "Candidature" }],
})
const Offre = mongoose.model("Offre", offreSchema, "offres")

// Schéma des candidatures
const candidatureSchema = new mongoose.Schema({
  id_offre: { type: mongoose.Schema.Types.ObjectId, ref: "Offre", required: true },
  id_candidat: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  cv: {
    filename: { type: String, required: true },
    contentType: { type: String, required: true },
    data: { type: String, required: true }, // Base64 encoded file data
    size: { type: Number, required: true },
  },
  lettre_motivation: {
    filename: { type: String, required: true },
    contentType: { type: String, required: true },
    data: { type: String, required: true }, // Base64 encoded file data
    size: { type: Number, required: true },
  },
  statut: { type: String, default: "en cours" },
  date_postulation: { type: Date, default: Date.now },
})

const Candidature = mongoose.model("Candidature", candidatureSchema, "candidatures")

const userSchema = new mongoose.Schema({
  nom: String,
  prenom: String,
  email: { type: String, unique: true, required: true },
  mot_de_passe: { type: String, required: true },
  role: { type: String, default: "candidat" },
})

const User = mongoose.model("User", userSchema, "users")

// S3 Client Configuration
const s3Client = new S3Client({
  region: process.env.AWS_REGION || "eu-west-3",
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
})
// Configure multer for memory storage (files will be in memory, not on disk)
const storage = multer.memoryStorage()
const upload = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit per file
  },
  fileFilter: (req, file, cb) => {
    // Accept only PDF, DOC, DOCX files
    const allowedTypes = [
      "application/pdf",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ]
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true)
    } else {
      cb(new Error("Type de fichier non autorisé. Seuls PDF, DOC et DOCX sont acceptés."))
    }
  },
})

// Helper function to convert file to Base64
function fileToBase64(file) {
  return {
    filename: file.originalname,
    contentType: file.mimetype,
    data: file.buffer.toString("base64"),
    size: file.size,
  }
}

// Helper function to upload file to S3
async function uploadFileToS3(file, folder) {
  const fileExtension = path.extname(file.originalname);
  const fileName = `${folder}/${uuidv4()}${fileExtension}`;

  const params = {
    Bucket: process.env.AWS_S3_BUCKET_NAME,
    Key: fileName,
    Body: file.buffer,
    ContentType: file.mimetype,
  };
  console.log('Uploading to S3 with params:', params);
  try {
    await s3Client.send(new PutObjectCommand(params));
  } catch (err) {
    console.error('Error uploading file to S3:', err);
    throw new Error('S3 upload failed');
  }
  return `https://${process.env.AWS_S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${fileName}`;
}

app.get("/", (req, res) => {
    res.send("Welcome to the API! Use /products to get data.");
});
app.get("/admin", async (req, res) => {
  try {
    const admin = await User.findOne({ role: "Admin" })
    if (!admin) {
      return res.status(404).json({ message: "Admin non trouvé" })
    }
    res.status(200).json(admin)
  } catch (err) {
    console.error("Erreur lors de la récupération de l'admin :", err)
    res.status(500).json({ error: "Erreur serveur" })
  }
})

app.post("/signup", async (req, res) => {
  const { nom, prenom, email, mot_de_passe, role } = req.body // Ajouter le rôle
  try {
    const existingUser = await User.findOne({ email })
    if (existingUser) {
      return res.status(400).json({ message: "Email déjà utilisé !" })
    }
    const hashedPassword = await bcrypt.hash(mot_de_passe, 10)
    const newUser = new User({ nom, prenom, email, mot_de_passe: hashedPassword, role }) // Inclure le rôle
    await newUser.save()
    res.status(201).json({ message: "Utilisateur enregistré avec succès !" })
  } catch (error) {
    res.status(500).json({ error: "Erreur lors de l'inscription" })
  }
})

app.post("/login", async (req, res) => {
  const { email, mot_de_passe } = req.body
  try {
    const user = await User.findOne({ email })
    console.log("Utilisateur trouvé :", user) // 🔍 Ajout du log

    if (!user) {
      return res.status(400).json({ message: "Email ou mot de passe incorrect !" })
    }

    const isMatch = await bcrypt.compare(mot_de_passe, user.mot_de_passe)
    console.log("Mot de passe valide :", isMatch) // 🔍 Vérification du mot de passe

    if (!isMatch) {
      return res.status(400).json({ message: "Email ou mot de passe incorrect !" })
    }

    const token = jwt.sign({ id: user._id, role: user.role }, "SECRET_KEY", { expiresIn: "24h" })
    res.status(200).json({ message: "Connexion réussie !", token, user })
  } catch (error) {
    console.error("❌ Erreur lors de la connexion :", error)
    res.status(500).json({ error: "Erreur lors de la connexion" })
  }
})

// Route to get all recruiters and candidates
app.get("/users", async (req, res) => {
  try {
    // Fetch recruiters (role = 'recruteur') and candidates (role = 'candidat')
    const recruteurs = await User.find({ role: "recruteur" })
    const candidats = await User.find({ role: "candidat" })

    // Return both recruiters and candidates in a single response
    res.status(200).json({ recruteurs, candidats })
  } catch (err) {
    console.error("Erreur lors de la récupération des utilisateurs", err)
    res.status(500).json({ error: "Erreur lors de la récupération des utilisateurs" })
  }
})

app.delete("/users/:id", async (req, res) => {
  try {
    const { id } = req.params

    const user = await User.findById(id)
    if (!user) {
      return res.status(404).json({ message: "User not found" })
    }

    if (user.role === "recruteur") {
      // ✅ FIRST: Get offers
      const offers = await Offre.find({ id_recruteur: id }).select("_id")
      const offerIds = offers.map((offer) => offer._id)

      // ✅ THEN: Delete candidatures
      if (offerIds.length > 0) {
        const deletedCandidatures = await Candidature.deleteMany({ id_offre: { $in: offerIds } })
        console.log(`Deleted ${deletedCandidatures.deletedCount} candidatures from recruiter's offers`)
      }

      // ✅ LAST: Delete the offers
      const deletedOffers = await Offre.deleteMany({ id_recruteur: id })
      console.log(`Deleted ${deletedOffers.deletedCount} job offers from recruiter ${id}`)
    }

    if (user.role === "candidat") {
      const deletedCandidatures = await Candidature.deleteMany({ id_candidat: id })
      console.log(`Deleted ${deletedCandidatures.deletedCount} candidatures from candidate ${id}`)
    }

    await User.findByIdAndDelete(id)

    res.status(200).json({ message: "User deleted successfully" })
  } catch (error) {
    console.error("Error deleting user:", error)
    res.status(500).json({ message: "Error deleting user", error: error.message })
  }
})

// Route to delete a job offer
app.delete("/offres/:id", async (req, res) => {
  try {
    const { id } = req.params

    // Check if offer exists
    const offer = await Offre.findById(id)
    if (!offer) {
      return res.status(404).json({ message: "Job offer not found" })
    }

    // Delete all candidatures for this offer
    const deletedCandidatures = await Candidature.deleteMany({ id_offre: id })
    console.log(`Deleted ${deletedCandidatures.deletedCount} candidatures for offer ${id}`)

    // Delete the offer
    await Offre.findByIdAndDelete(id)

    res.status(200).json({ message: "Job offer deleted successfully" })
  } catch (error) {
    console.error("Error deleting job offer:", error)
    res.status(500).json({ message: "Error deleting job offer", error: error.message })
  }
})

// Route pour récupérer toutes les offres
app.get("/offres", async (req, res) => {
  try {
    const { titre, lieu } = req.query
    const filter = {}
    if (titre) filter.titre = { $regex: titre, $options: "i" }
    if (lieu) filter.lieu = { $regex: lieu, $options: "i" }

    // Limit the results to 6 for the initial fetch
    const offres = await Offre.find(filter).limit(6)
    res.status(200).json(offres || []) // Ensure an empty array is returned
  } catch (err) {
    res.status(500).json({ error: "Erreur lors de la récupération des offres" })
  }
})

app.post("/offres", async (req, res) => {
  const { titre, description, entreprise, lieu, salaire, id_recruteur } = req.body

  // Validation: Ensure all required fields are present
  if (!titre || !description || !entreprise || !lieu || !id_recruteur) {
    return res.status(400).json({ message: "Tous les champs requis doivent être remplis !" })
  }

  try {
    const newOffre = new Offre({
      titre,
      description,
      entreprise,
      lieu,
      salaire: salaire || 0, // Default to 0 if not provided
      date_publication: new Date(),
      id_recruteur,
    })

    await newOffre.save()
    res.status(201).json({ message: "Offre ajoutée avec succès", offre: newOffre })
  } catch (error) {
    console.error("❌ Erreur lors de l'ajout de l'offre:", error)
    res.status(500).json({ message: "Erreur lors de l'ajout de l'offre", error })
  }
})

app.get("/filters", async (req, res) => {
  try {
    const villes = await Offre.distinct("lieu")
    const titres = await Offre.distinct("titre")
    res.json({ villes, titres })
  } catch (err) {
    res.status(500).json({ error: "Erreur lors de la récupération des filtres" })
  }
})

// Route pour récupérer une offre spécifique avec détails
app.get("/offre/:id", async (req, res) => {
  try {
    console.log("🔍 Fetching offer with ID:", req.params.id)

    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "ID d'offre invalide" })
    }

    // Populate candidatures but EXCLUDE the heavy Base64 file data
    const offre = await Offre.findById(req.params.id).populate({
      path: "candidatures",
      select: "-cv.data -lettre_motivation.data", // ✅ EXCLUDE Base64 data
      populate: {
        path: "id_candidat",
        select: "nom prenom email", // Only basic candidate info
      },
    })

    if (!offre) {
      return res.status(404).json({ message: "Offre non trouvée" })
    }

    console.log("✅ Offer fetched successfully")
    res.json(offre)
  } catch (err) {
    console.error("❌ Error in /offre/:id route:", err)
    res.status(500).json({
      message: "Erreur serveur",
      error: err.message || "Unknown error",
    })
  }
})


 const verifyToken = (req, res, next) => {
            const token = req.header("Authorization"); // "Bearer ey..."
        
            if (!token) {
                return res.status(403).json({ message: "Accès refusé. Aucun token fourni." });
            }
        
            try {
                // Remove "Bearer " if present
                const actualToken = token.replace("Bearer ", "");
                
                // Verify the token
                const decoded = jwt.verify(actualToken, "SECRET_KEY");
                req.user = decoded; // Pass user data to next middleware
                next();
            } catch (err) {
                if (err.name === "TokenExpiredError") {
                    return res.status(401).json({ message: "Erreur de vérification de token: Token expiré." });
                } else if (err.name === "JsonWebTokenError") {
                    return res.status(401).json({ message: "Token invalide." });
                } else {
                    return res.status(500).json({ message: "Erreur lors de la vérification du token." });
                }
            }
        };
        

// UPDATED: Route for submitting a job application with cloud storage
app.post(
  "/candidature",
  verifyToken,
  upload.fields([{ name: "cv" }, { name: "lettre_motivation" }]),
  async (req, res) => {
    try {
      const { id_offre } = req.body

      // Validate offer ID
      if (!mongoose.Types.ObjectId.isValid(id_offre)) {
        return res.status(400).json({ message: "ID d'offre invalide" })
      }

      // Check if files are provided
      if (!req.files?.cv || !req.files?.lettre_motivation) {
        return res.status(400).json({ message: "CV et lettre de motivation sont requis" })
      }

      console.log("Files received:", {
        cv: req.files.cv[0].originalname,
        lettre: req.files.lettre_motivation[0].originalname,
      })

      // Convert files to Base64
      const cvData = fileToBase64(req.files.cv[0])
      const lettreData = fileToBase64(req.files.lettre_motivation[0])

      console.log("Files converted to Base64 successfully")

      // Create new candidature with file data
      const newCandidature = new Candidature({
        id_offre,
        id_candidat: req.user.id,
        cv: cvData,
        lettre_motivation: lettreData,
        statut: "en cours",
        date_postulation: new Date(),
      })

      // Save candidature to database
      await newCandidature.save()
      console.log("Candidature saved to database:", newCandidature._id)

      // Update the offer with the new candidature
      await Offre.findByIdAndUpdate(id_offre, {
        $push: { candidatures: newCandidature._id },
      })

      res.status(201).json({
        message: "Candidature envoyée avec succès",
        candidature: {
          _id: newCandidature._id,
          id_offre: newCandidature.id_offre,
          id_candidat: newCandidature.id_candidat,
          statut: newCandidature.statut,
          date_postulation: newCandidature.date_postulation,
          cv: { filename: cvData.filename, size: cvData.size },
          lettre_motivation: { filename: lettreData.filename, size: lettreData.size },
        },
      })
    } catch (err) {
      console.error("Error in /candidature route:", err)

      if (err.message.includes("Type de fichier non autorisé")) {
        return res.status(400).json({
          message: err.message,
        })
      }

      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(400).json({
          message: "Fichier trop volumineux. Taille maximale: 10MB",
        })
      }

      res.status(500).json({
        message: "Erreur lors de la soumission de la candidature",
        error: err.message,
      })
    }
  },
)
app.get("/candidature/:id/cv", verifyToken, async (req, res) => {
  try {
    console.log("📄 Fetching CV for candidature:", req.params.id);
    const candidature = await Candidature.findById(req.params.id);

    if (!candidature || !candidature.cv) {
      console.log("❌ CV not found");
      return res.status(404).json({ message: "CV non trouvé" });
    }

    console.log("✅ CV found, filename:", candidature.cv.filename);
    console.log("✅ Content type:", candidature.cv.contentType);
    console.log("✅ File size:", candidature.cv.size);

    // Convert Base64 back to buffer
    const fileBuffer = Buffer.from(candidature.cv.data, "base64");

    // Enhanced headers for better browser compatibility
    res.set({
      "Content-Type": candidature.cv.contentType,
      "Content-Disposition": `inline; filename="${candidature.cv.filename}"`,
      "Content-Length": fileBuffer.length,
      "Cache-Control": "public, max-age=86400",
      // Add CORS headers for blob handling
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Expose-Headers": "Content-Type, Content-Disposition, Content-Length"
    });

    res.send(fileBuffer);
  } catch (err) {
    console.error("❌ Error downloading CV:", err);
    res.status(500).json({ message: "Erreur lors du téléchargement du CV", error: err.message });
  }
});
// Route to download lettre de motivation file
app.get("/candidature/:id/lettre", verifyToken, async (req, res) => {
  try {
    const candidature = await Candidature.findById(req.params.id)

    if (!candidature || !candidature.lettre_motivation) {
      return res.status(404).json({ message: "Lettre de motivation non trouvée" })
    }

    // Convert Base64 back to buffer
    const fileBuffer = Buffer.from(candidature.lettre_motivation.data, "base64")

    res.set({
      "Content-Type": candidature.lettre_motivation.contentType,
      "Content-Disposition": `attachment; filename="${candidature.lettre_motivation.filename}"`,
      "Content-Length": fileBuffer.length,
    })

    res.send(fileBuffer)
  } catch (err) {
    console.error("Error downloading lettre:", err)
    res.status(500).json({ message: "Erreur lors du téléchargement de la lettre" })
  }
})

        
app.get("/me", async (req, res) => {
  const authHeader = req.headers.authorization
  if (!authHeader) {
    return res.status(401).json({ message: "Token manquant" })
  }

  const token = authHeader.split(" ")[1]

  try {
    const decoded = jwt.verify(token, "SECRET_KEY")

    const user = await User.findById(decoded.id)
    if (!user) {
      return res.status(404).json({ message: "Utilisateur non trouvé" })
    }

    res.json({ user })
  } catch (error) {
    console.error("Erreur de vérification de token:", error)
    res.status(401).json({ message: "Token invalide" })
  }
})

app.get("/mes-candidatures", verifyToken, async (req, res) => {
  try {
    const candidatures = await Candidature.find({ id_candidat: req.user.id })
      .populate("id_offre", "titre entreprise lieu") // pour avoir les infos de l'offre
      .sort({ date_postulation: -1 })

    res.status(200).json(candidatures)
  } catch (err) {
    res.status(500).json({ message: "Erreur lors de la récupération des candidatures", error: err })
  }
})

app.get("/offres/recruteur/:id", async (req, res) => {
  // Ajout de async ici
  const id = req.params.id
  console.log("ID reçu:", id)

  try {
    const offres = await Offre.find({ id_recruteur: id }) // Correction ici aussi
    res.status(200).json(offres)
  } catch (error) {
    console.error("Erreur serveur:", error) // Ajout d'un log d'erreur
    res.status(500).json({ message: "Erreur serveur", error: error.message })
  }
})

// Route pour récupérer les candidatures liées à un recruteur
app.get("/candidatures", verifyToken, async (req, res) => {
  try {
    // Récupérer les offres créées par le recruteur connecté
    const offres = await Offre.find({ id_recruteur: req.recruteurId }).select("_id")

    if (!offres.length) {
      return res.status(200).json([]) // Aucun résultat si le recruteur n'a pas d'offres
    }

    // Extraire les IDs des offres
    const offreIds = offres.map((offre) => offre._id)

    // Trouver les candidatures associées à ces offres
    const candidatures = await Candidature.find({ id_offre: { $in: offreIds } })
      .populate("id_offre", "titre entreprise")
      .exec()

    res.status(200).json(candidatures)
  } catch (err) {
    res.status(500).json({ message: "Erreur lors de la récupération des candidatures", error: err })
  }
})

app.get("/candidatures/:recruteurId", async (req, res) => {
  try {
    const { recruteurId } = req.params
    console.log("🔍 Recruteur ID reçu :", recruteurId)

    // Récupérer les offres de ce recruteur
    const offres = await Offre.find({ id_recruteur: recruteurId }).select("_id")

    if (offres.length === 0) {
      return res.status(404).json({ message: "Aucune offre trouvée pour ce recruteur" })
    }

    const offreIds = offres.map((offre) => offre._id)
    console.log("📋 Offres trouvées :", offreIds)

    // Récupérer les candidatures liées à ces offres
    const candidatures = await Candidature.find({ id_offre: { $in: offreIds } }).populate("id_offre")
    console.log("📥 Candidatures trouvées :", candidatures)

    res.status(200).json(candidatures)
  } catch (error) {
    console.error("❌ Erreur lors de la récupération des candidatures :", error)
    res.status(500).json({ error: "Erreur serveur" })
  }
})

app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "script-src 'self' https://apis.google.com https://accounts.google.com")
  next()
})

// UPDATED: Route for updating interview scheduling with cloud storage
app.post("/planifier-entretien/:id", upload.single("cv"), async (req, res) => {
  try {
    const { id } = req.params
    const { date_entretien } = req.body

    // Vérifier si la candidature existe
    const candidature = await Candidature.findById(id)
    if (!candidature) {
      return res.status(404).json({ message: "Candidature non trouvée" })
    }

    // Mettre à jour la candidature avec la date de l'entretien et le CV si fourni
    const updateData = { date_entretien }
    if (req.file) {
      const cvUrl = await uploadFileToS3(req.file, "cvs")
      updateData.cv = cvUrl
    }

    await Candidature.findByIdAndUpdate(id, updateData, { new: true })

    res.status(200).json({ message: "Entretien planifié avec succès !" })
  } catch (err) {
    res.status(500).json({ message: "Erreur lors de la planification de l'entretien", error: err })
  }
})

// Route pour mettre à jour le statut d'une candidature
app.put("/candidatures/:id/statut", async (req, res) => {
  const { id } = req.params
  const { statut } = req.body

  try {
    const updatedCandidature = await Candidature.findByIdAndUpdate(id, { statut }, { new: true })
    if (!updatedCandidature) {
      return res.status(404).json({ message: "Candidature non trouvée" })
    }
    res.json({ message: "Statut mis à jour avec succès", candidature: updatedCandidature })
  } catch (error) {
    res.status(500).json({ error: "Erreur lors de la mise à jour du statut" })
  }
})

// Route pour récupérer les candidatures acceptées
app.get("/candidatures/confirmees/:recruteurId", async (req, res) => {
  try {
    const { recruteurId } = req.params
    console.log("🔍 Recruteur ID reçu :", recruteurId)

    // Récupérer les offres de ce recruteur
    const offres = await Offre.find({ id_recruteur: recruteurId }).select("_id")

    if (!offres.length) {
      return res.status(200).json({ message: "Aucune offre trouvée pour ce recruteur" })
    }

    // Extraire les IDs des offres
    const offreIds = offres.map((offre) => offre._id)

    // Trouver les candidatures confirmées associées à ces offres
    const candidaturesConfirmees = await Candidature.find({
      id_offre: { $in: offreIds },
      statut: "acceptée",
    })
      .populate("id_offre", "titre entreprise")
      .exec()

    res.status(200).json(candidaturesConfirmees)
  } catch (err) {
    res.status(500).json({ message: "Erreur lors de la récupération des candidatures confirmées", error: err })
  }
})

app.get("/candidatures/statistiques/:recruteurId", async (req, res) => {
  try {
    const { recruteurId } = req.params
    console.log("🔍 Recruteur ID reçu :", recruteurId)

    // Récupérer les offres créées par le recruteur
    const offres = await Offre.find({ id_recruteur: recruteurId }).select("_id")

    if (!offres.length) {
      return res.status(200).json({
        message: "Aucune offre trouvée pour ce recruteur",
        statistiques: { en_cours: 0, refusees: 0, acceptees: 0 },
      })
    }

    // Extraire les IDs des offres
    const offreIds = offres.map((offre) => offre._id)

    // Compter les candidatures en fonction de leur statut
    const statistiques = await Candidature.aggregate([
      { $match: { id_offre: { $in: offreIds } } },
      { $group: { _id: "$statut", count: { $sum: 1 } } },
    ])

    // Transformer les résultats en un objet plus lisible
    const stats = {
      en_cours: 0,
      refusees: 0,
      acceptees: 0,
    }

    statistiques.forEach((stat) => {
      if (stat._id === "en cours") stats.en_cours = stat.count
      if (stat._id === "refusée") stats.refusees = stat.count
      if (stat._id === "acceptée") stats.acceptees = stat.count
    })

    res.status(200).json({ recruteurId, statistiques: stats })
  } catch (err) {
    res.status(500).json({ message: "Erreur lors de la récupération des statistiques des candidatures", error: err })
  }
})

// Démarrer le serveur
app.listen(PORT, () => {
  console.log(`🚀 Serveur en cours d'exécution sur http://localhost:${PORT}`)
})

module.exports = app
