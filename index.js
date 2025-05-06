require("dotenv").config()
const express = require("express")
const mongoose = require("mongoose")
const cors = require("cors")
const multer = require("multer")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const app = express()
const PORT = process.env.PORT || 5050

// Middleware
app.use(express.json())
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
)

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB Atlas Connected"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err))

// Import schemas
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

const candidatureSchema = new mongoose.Schema({
  id_offre: { type: mongoose.Schema.Types.ObjectId, ref: "Offre", required: true },
  id_candidat: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  cv: String,
  lettre_motivation: String,
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

// Token verification middleware
const verifyToken = (req, res, next) => {
  const token = req.header("Authorization")

  if (!token) {
    return res.status(403).json({ message: "Accès refusé. Aucun token fourni." })
  }

  try {
    const actualToken = token.replace("Bearer ", "")
    const decoded = jwt.verify(actualToken, "SECRET_KEY")
    req.user = decoded
    next()
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token expiré." })
    } else if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ message: "Token invalide." })
    } else {
      return res.status(500).json({ message: "Erreur lors de la vérification du token." })
    }
  }
}

// Configure multer for file uploads
// Use memory storage which works in both environments
const storage = multer.memoryStorage()
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
})

// Routes
app.get("/", (req, res) => {
  res.send("Bienvenue sur l'API ! Utilisez /offres pour récupérer les offres d'emploi.")
})

// User routes
app.post("/signup", async (req, res) => {
  const { nom, prenom, email, mot_de_passe, role } = req.body
  try {
    const existingUser = await User.findOne({ email })
    if (existingUser) {
      return res.status(400).json({ message: "Email déjà utilisé !" })
    }
    const hashedPassword = await bcrypt.hash(mot_de_passe, 10)
    const newUser = new User({ nom, prenom, email, mot_de_passe: hashedPassword, role })
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

    if (!user) {
      return res.status(400).json({ message: "Email ou mot de passe incorrect !" })
    }

    const isMatch = await bcrypt.compare(mot_de_passe, user.mot_de_passe)
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

// Job offer routes
app.get("/offres", async (req, res) => {
  try {
    const { titre, lieu } = req.query
    const filter = {}
    if (titre) filter.titre = { $regex: titre, $options: "i" }
    if (lieu) filter.lieu = { $regex: lieu, $options: "i" }

    const offres = await Offre.find(filter).limit(6)
    res.status(200).json(offres || [])
  } catch (err) {
    res.status(500).json({ error: "Erreur lors de la récupération des offres" })
  }
})

app.post("/offres", async (req, res) => {
  const { titre, description, entreprise, lieu, salaire, id_recruteur } = req.body

  if (!titre || !description || !entreprise || !lieu || !id_recruteur) {
    return res.status(400).json({ message: "Tous les champs requis doivent être remplis !" })
  }

  try {
    const newOffre = new Offre({
      titre,
      description,
      entreprise,
      lieu,
      salaire: salaire || 0,
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

app.get("/offre/:id", async (req, res) => {
  try {
    const offre = await Offre.findById(req.params.id).populate("candidatures")
    if (!offre) return res.status(404).json({ message: "Offre non trouvée" })
    res.json(offre)
  } catch (err) {
    res.status(500).json({ message: "Erreur serveur", error: err })
  }
})

// Modified candidature route to work in both environments
app.post("/candidature", verifyToken, (req, res) => {
  // Create a multer instance for this specific request
  const uploadFields = upload.fields([
    { name: "cv", maxCount: 1 },
    { name: "lettre_motivation", maxCount: 1 },
  ])

  // Handle the file upload
  uploadFields(req, res, async (err) => {
    if (err instanceof multer.MulterError) {
      // A Multer error occurred when uploading
      console.error("Multer error:", err)
      return res.status(400).json({ message: `Erreur lors du téléchargement: ${err.message}` })
    } else if (err) {
      // An unknown error occurred
      console.error("Unknown error:", err)
      return res.status(500).json({ message: `Erreur inconnue: ${err.message}` })
    }

    try {
      const { id_offre } = req.body

      if (!mongoose.Types.ObjectId.isValid(id_offre)) {
        return res.status(400).json({ message: "ID d'offre invalide" })
      }

      if (!req.files?.cv || !req.files?.lettre_motivation) {
        return res.status(400).json({ message: "CV et lettre de motivation sont requis" })
      }

      // Convert files to Base64 strings
      const cvBase64 = req.files.cv[0].buffer.toString("base64")
      const lettreBase64 = req.files.lettre_motivation[0].buffer.toString("base64")

      // Store file metadata along with Base64 content
      const cvData = {
        filename: req.files.cv[0].originalname,
        contentType: req.files.cv[0].mimetype,
        data: cvBase64,
      }

      const lettreData = {
        filename: req.files.lettre_motivation[0].originalname,
        contentType: req.files.lettre_motivation[0].mimetype,
        data: lettreBase64,
      }

      const newCandidature = new Candidature({
        id_offre,
        id_candidat: req.user.id,
        cv: JSON.stringify(cvData),
        lettre_motivation: JSON.stringify(lettreData),
      })

      await newCandidature.save()
      await Offre.findByIdAndUpdate(id_offre, { $push: { candidatures: newCandidature._id } })

      res.status(201).json({
        message: "Candidature envoyée avec succès",
        candidature: {
          ...newCandidature.toObject(),
          cv: cvData.filename,
          lettre_motivation: lettreData.filename,
        },
      })
    } catch (err) {
      console.error("Erreur lors de la soumission:", err)
      res.status(500).json({ message: "Erreur lors de la soumission de la candidature." })
    }
  })
})

// Other routes (add the rest of your routes here)
app.get("/mes-candidatures", verifyToken, async (req, res) => {
  try {
    const candidatures = await Candidature.find({ id_candidat: req.user.id })
      .populate("id_offre", "titre entreprise lieu")
      .sort({ date_postulation: -1 })

    res.status(200).json(candidatures)
  } catch (err) {
    res.status(500).json({ message: "Erreur lors de la récupération des candidatures", error: err })
  }
})

 app.get("/me", async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: "Token manquant" });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, "SECRET_KEY");

        const user = await User.findById(decoded.id);
        if (!user) {
        return res.status(404).json({ message: "Utilisateur non trouvé" });
        }

        res.json({ user });
    } catch (error) {
        console.error("Erreur de vérification de token:", error);
        res.status(401).json({ message: "Token invalide" });
    }
    });

    app.get('/offres/recruteur/:id', async (req, res) => { // Ajout de async ici
        const id = req.params.id;
        console.log("ID reçu:", id);
        
        try {
            const offres = await Offre.find({ id_recruteur: id }); // Correction ici aussi
            res.status(200).json(offres);
        } catch (error) {
            console.error("Erreur serveur:", error); // Ajout d'un log d'erreur
            res.status(500).json({ message: "Erreur serveur", error: error.message });
        }
    });
      app.get("/candidatures", verifyToken, async (req, res) => {
                try {
                    // Récupérer les offres créées par le recruteur connecté
                    const offres = await Offre.find({ id_recruteur: req.recruteurId }).select("_id");
            
                    if (!offres.length) {
                        return res.status(200).json([]); // Aucun résultat si le recruteur n'a pas d'offres
                    }
            
                    // Extraire les IDs des offres
                    const offreIds = offres.map(offre => offre._id);
            
                    // Trouver les candidatures associées à ces offres
                    const candidatures = await Candidature.find({ id_offre: { $in: offreIds } })
                        .populate("id_offre", "titre entreprise")
                        .exec();
            
                    res.status(200).json(candidatures);
                } catch (err) {
                    res.status(500).json({ message: "Erreur lors de la récupération des candidatures", error: err });
                }
            });
            
            app.get("/candidatures/:recruteurId", async (req, res) => {
                try {
                    const { recruteurId } = req.params;
                    console.log("🔍 Recruteur ID reçu :", recruteurId);
            
                    // Récupérer les offres de ce recruteur
                    const offres = await Offre.find({ id_recruteur: recruteurId }).select("_id");
            
                    if (offres.length === 0) {
                        return res.status(404).json({ message: "Aucune offre trouvée pour ce recruteur" });
                    }
            
                    const offreIds = offres.map(offre => offre._id);
                    console.log("📋 Offres trouvées :", offreIds);
            
                    // Récupérer les candidatures liées à ces offres
                    const candidatures = await Candidature.find({ id_offre: { $in: offreIds } }).populate("id_offre");
                    console.log("📥 Candidatures trouvées :", candidatures);
            
                    res.status(200).json(candidatures);
                } catch (error) {
                    console.error("❌ Erreur lors de la récupération des candidatures :", error);
                    res.status(500).json({ error: "Erreur serveur" });
                }
            });
            
            app.use((req, res, next) => {
                res.setHeader("Content-Security-Policy", "script-src 'self' https://apis.google.com https://accounts.google.com");
                next();
            });
            
            // Route pour mettre à jour le statut d'une candidature
        app.put("/candidatures/:id/statut", async (req, res) => {
            const { id } = req.params;
            const { statut } = req.body;
    
            try {
                const updatedCandidature = await Candidature.findByIdAndUpdate(id, { statut }, { new: true });
                if (!updatedCandidature) {
                    return res.status(404).json({ message: "Candidature non trouvée" });
                }
                res.json({ message: "Statut mis à jour avec succès", candidature: updatedCandidature });
            } catch (error) {
                res.status(500).json({ error: "Erreur lors de la mise à jour du statut" });
            }
        });
    
        // Route pour récupérer les candidatures acceptées
        app.get("/candidatures/confirmees/:recruteurId", async (req, res) => {
            try {
                const { recruteurId } = req.params;
                console.log("🔍 Recruteur ID reçu :", recruteurId);
    
                // Récupérer les offres de ce recruteur
                const offres = await Offre.find({ id_recruteur: recruteurId }).select("_id");
    
                if (!offres.length) {
                    return res.status(200).json({ message: "Aucune offre trouvée pour ce recruteur" });
                }
    
                // Extraire les IDs des offres
                const offreIds = offres.map(offre => offre._id);
    
                // Trouver les candidatures confirmées associées à ces offres
                const candidaturesConfirmees = await Candidature.find({ 
                    id_offre: { $in: offreIds }, 
                    statut: "acceptée" 
                })
                .populate("id_offre", "titre entreprise")
                .exec();
    
                res.status(200).json(candidaturesConfirmees);
            } catch (err) {
                res.status(500).json({ message: "Erreur lors de la récupération des candidatures confirmées", error: err });
            }
        });
    
    
        // Route pour mettre à jour une candidature avec la planification d'entretien
        app.post("/planifier-entretien/:id", upload.single("cv"), async (req, res) => {
            try {
                const { id } = req.params;
                const { date_entretien } = req.body;
    
                // Vérifier si la candidature existe
                const candidature = await Candidature.findById(id);
                if (!candidature) {
                    return res.status(404).json({ message: "Candidature non trouvée" });
                }
    
                // Mettre à jour la candidature avec la date de l'entretien et le CV si fourni
                let updateData = { date_entretien };
                if (req.file) {
                    updateData.cv = req.file.path;
                }
    
                await Candidature.findByIdAndUpdate(id, updateData, { new: true });
    
                res.status(200).json({ message: "Entretien planifié avec succès !" });
            } catch (err) {
                res.status(500).json({ message: "Erreur lors de la planification de l'entretien", error: err });
            }
        });
        app.get("/candidatures/statistiques/:recruteurId", async (req, res) => {
            try {
                const { recruteurId } = req.params;
                console.log("🔍 Recruteur ID reçu :", recruteurId);
    
                // Récupérer les offres créées par le recruteur
                const offres = await Offre.find({ id_recruteur: recruteurId }).select("_id");
    
                if (!offres.length) {
                    return res.status(200).json({ 
                        message: "Aucune offre trouvée pour ce recruteur", 
                        statistiques: { en_cours: 0, refusees: 0, acceptees: 0 } 
                    });
                }
    
                // Extraire les IDs des offres
                const offreIds = offres.map(offre => offre._id);
    
                // Compter les candidatures en fonction de leur statut
                const statistiques = await Candidature.aggregate([
                    { $match: { id_offre: { $in: offreIds } } },
                    { $group: { _id: "$statut", count: { $sum: 1 } } }
                ]);
    
                // Transformer les résultats en un objet plus lisible
                const stats = {
                    en_cours: 0,
                    refusees: 0,
                    acceptees: 0
                };
    
                statistiques.forEach(stat => {
                    if (stat._id === "en cours") stats.en_cours = stat.count;
                    if (stat._id === "refusée") stats.refusees = stat.count;
                    if (stat._id === "acceptée") stats.acceptees = stat.count;
                });
    
                res.status(200).json({ recruteurId, statistiques: stats });
            } catch (err) {
                res.status(500).json({ message: "Erreur lors de la récupération des statistiques des candidatures", error: err });
            }
        });
// Start server only in local environment
// In Vercel, this is handled by the serverless function
if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => {
    console.log(`🚀 Serveur en cours d'exécution sur http://localhost:${PORT}`)
  })
}

// Export the Express app for Vercel
module.exports = app
